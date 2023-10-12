# Security Evaluation of curl

Written in collaberation with Michael Choi, Theodore Lau, Adam Murtagh, Sami Hamide, Alexander West for UCLA CS 136, Computer Security.


# Summary

In this report, we assess and rate the security of version 8.0.1 of the well-known command-line URL data transfer tool curl. We approached this analysis from three angles — researching previous vulnerabilities, conceptually scrutinizing curl’s design, and running analysis tools on the actual 8.0.1 code. Through this analysis, we have discovered common patterns for insecure coding, concrete tools with which to perform security analyses, and more efficient ways to approach security analyses in the future. With the results we have gathered, we conclude that curl 8.0.1 is reasonably secure.


# Plan

In our first meeting, we reviewed the spec’s suggestions for evaluation approaches and brainstormed several of our own. We then delegated each approach to a team member to work on between meetings. The overall analysis process our team took can be summarized in roughly five steps:



1. Getting to know curl better at a high level,
2. Researching previous vulnerabilities,
3. Conjecturing design flaws,
4. Running curl through automated analysis tools, and
5. Manual code review.

To facilitate our progress, we also held regular meetings, during which we reported on individual work, discussed and realigned our process, and re-delegated tasks as needed. In total, we held three meetings, each of which had a main overall focus:

- Meeting 1:	Determining and assigning tasks (approaches)
- Meeting 2:	First check-in and recording our first results
- Meeting 3:	Summarizing our results and polishing up the paper

In the end, we followed up on five main approaches, which are laid out in more detail in the 

[Results](#results) section:



1. Examining previously documented vulnerabilities — Theodore Lau
2. Performing a security design review — Adam Murtagh
3. Analyzing the implications of modifying curl’s extensible components (libraries/backends) — Sami Hamide
4. Passing the source code through static analysis tools — Alexander West
5. Running fuzz tests on the compiled executable — Michael Choi

These approaches were aided in large part by the following tools:



* Flawfinder[^1] — an open source static analyzer


* American Fuzzy Lop[^2] — a fuzz testing tool suite
Our most major deviation from our initial plan was in regards to step V of our analysis process — manual code review. At first, our group did not use automated tools as comprehensively as we eventually would and attempted to parse through much of the code by hand, which quickly proved too much to feasibly handle. This issue was alleviated after becoming more familiar with the automated tools we used, which allowed us to scan through larger portions of code with more precision.


# Results


## Previously Documented Vulnerabilities

As of the writing of this report, four vulnerabilities have been documented for curl 8.0.1 on curl’s official website[^3]. From most severe to least, they are:



* CVE-2023-28319: UAF in SSH sha256 fingerprint check
* CVE-2023-28322: more POST-after-PUT confusion
* CVE-2023-28320: siglongjmp race condition
* CVE-2023-28321: IDN wildcard match

We describe in more detail two of the more serious vulnerabilities:


### UAF in SSH sha256 fingerprint check


#### Vulnerability

This vulnerability can be described as a “use after free” bug. Curl can enter this unsafe state after failing to verify an SSH server’s public key with SHA-256. The memory storing the SHA-256 fingerprint is freed and then immediately read and written to an error message buffer, which might later be exposed in a debugging log. We quote the code, with its problematic lines highlighted:


###### lib/vssh/libssh2.c, lines 729-739


```
if((pub_pos != b64_pos) ||
   strncmp(fingerprint_b64, pubkey_sha256, pub_pos)) {
  free(fingerprint_b64);

  failf(data,
        "Denied establishing ssh session: mismatch sha256 fingerprint. "
        "Remote %s is not equal to %s", fingerprint_b64, pubkey_sha256);
  state(data, SSH_SESSION_FREE);
  sshc->actualcode = CURLE_PEER_FAILED_VERIFICATION;
  return sshc->actualcode;
}
```



#### Potential Exploit

We lay out a procedure to potentially extract sensitive information from a target system:



1. Configure an SSH server with an invalid SHA-256 public key.
2. Have the target use curl to contact the server.
3. Read the curl error log on the target.

This exploit requires, however, many prerequisites to be fulfilled to produce valuable information. The target must first fully perform and fail the hash check, which requires the target’s libcurl to be built with libssh2, have the URLOPT_SSH_HOST_PUBLIC_KEY_SHA256 option set, and either the CURLOPT_VERBOSE or CURLOPT_ERRORBUFFER option also set. The thread running curl must also be interrupted right after line 731 in the quoted code above executes. The target system must then write sensitive information to the memory that was just freed, perhaps in another thread with shared memory. The last requirement is to extract the error log from the target, in the likely case that it is not already readily accessible.


#### Patch

By simply moving line 731 below line 735, the vulnerability no longer presents itself. Even without changing the source code, “failf” executes so soon after “fingerprint_b64” is freed that there will not be many instances of sensitive information being written to the memory of “fingerprint_b64,” which will then get written out. Even if sensitive information is written out, it is limited to 210 bytes of information, as described in a response to this [HackerOne post](https://hackerone.com/reports/1913733)[^4].


### more POST-after-PUT confusion


#### Vulnerability

This vulnerability can also be described as a form of “use after free” bug, and is a remnant of a previous POST-after-PUT vulnerability. If a handle has issued a PUT request, libcurl can use the read callback function despite the CURLOPT_POSTFIELDS option having already been set, resulting in misbehavior or using memory after it has been freed. We quote an example of code where this could occur:


```
CURL *curl = curl_easy_init(); 

if(curl) { 
const char *data = "data to send"; 

curl_easy_setopt(curl, CURLOPT_URL, "https://example.com"); 

/* size of the POST data */ 
curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 12L); 

/* pass in a pointer to the data - libcurl will not copy */ 
curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data); 

curl_easy_perform(curl); 
}
```



#### Potential Exploit

We lay out a procedure to potentially extract sensitive information from a target system:



1. Determine if a service is using libcurl in the manner described above, perhaps by looking through source code if the service is open source.
2. Make requests of the service that cause this code to be run.
3. See what data is delivered, as the wrong data (which may potentially be sensitive) may have been sent. 

This exploit requires significant reliance on random chance, meaning it could work instantly or take millions of hours to produce anything of worth to the attacker. Sensitive information has to have just been written to the memory that was just freed.


#### Patch

By changing the source code’s logic to only have one variable field hold information about the HTTP method and behavior, libcurl code should never be in a state where this bug occurs. This is because the source of this bug is that there are two fields, CURLOPT_POST and CURLOPT_POSTFIELDS, and setting only the latter allows the misbehavior. By making it only one field, this potential is erased.


## Design Review

After examining several curl resources, including the comprehensive manual and the curl source code on GitHub, these are overarching design choices that may create potential vulnerabilities that we have found:


### Protocol Usage

Curl allows its user to have some control over the protocol used to perform transfers. Normally the protocol specified in the beginning of the given URL is used as is, but in the case of insecure protocols such as HTTP or FTP, a user is able to use the “-s” option to attempt to use the SSL version of the protocol instead. This ability means that a naive user is able to use an insecure protocol to transfer sensitive information, even when a more secure version of the protocol is available, creating risk in exchange for user choice. A more secure method would be to always use the secure version of a protocol by default, perhaps warning the user and making them actively approve using an insecure protocol for the transfer to continue.


### Default Config Files

Curl specifies that whenever it is invoked, it attempts to locate a default config file and uses it if one is found unless the “-q” option is selected or a user specifies their own config file. This config file is able to specify any number of command line options, as its purpose is to allow many complicated and lengthy options to be specified without having them clog the command line. This means that anyone with access to the system, such as a disgruntled employee, could alter the default config file in any number of ways, such as extending the default timeout length, maximum file length, removing upgrades to more secure protocols as specified above, etc. This serves as a quasi backdoor, introducing a vulnerability that only the saboteur is aware of until it’s too late. Typical security methods for file write permissions would help to make the default config file more secure, preventing anyone other than the most privileged users from altering it. 


### Largest Download Size

Curl allows a user to specify the maximum size of the file that will be transferred in bytes, which will be compared to the size of the actual file queued to transfer. If they are incompatible, curl will exit with code 63. However, it is noted in both CURLOPT_MAXFILESIZE3 and the curl manual that in many cases, file size is not known before a transfer occurs and that the “--max-filesize” option will not do anything in those cases. A potential attacker could take advantage of this, unloading massive files when a server or client expects smaller ones by making sure that a file’s size cannot be known prior to transfer. This is especially effective when done to a rapid series of small file transfers, consuming memory/storage in order to disable the target system. It is also notable that unless the “--remove-on-error” option is also specified, any errors will not cause partially transferred files to be deleted, meaning they will still consume memory/storage. This also has possibilities for some form of suppress-replay attack, using inflated file sizes to delay transfers. 

Having the user specifically opt in to files of unknown size being transferred when a maximum file size is specified would prevent such an attack, at least when a user is not performing a task that requires files of unknown sizes to be transferred and thus has no other choice. Implementing an option to not just delete the fully transferred file on error, but to also delete the transferred file if a post-transfer comparison between it and the given max file size finds it exceeds the maximum would also help prevent an attacker from filling the target system.


### Connection Reuse

Libcurl maintains a cache of connections, allowing it to check if a new command can use one of these existing connections instead of establishing a new one in order to save a significant amount of time and resources. However, using such a cache should make it vulnerable to something similar to a SYN Flood, where a malicious user fills the cache with useless connections in order to slow down or even disable the service using curl. In order to increase security from such an attack, measures similar to what are used to defend against SYN Floods could be employed, such as implementing a cookie system based on IP, timestamp, port, etc that would make sure the connections being saved are valid.


## Implications of Disabling Libraries

Curl, by its design, relies on third party implementation of specific network protocol libraries. These include TLS, SSL, FTP, HTTP and even offering configuration for other "BwiD" style TCP/IP libraries. Most programmers and security researchers will know this extensibility into other programs provides the necessary circumstance for a potential Middleware attack. In the case of curl, an attack could be custom created for any of these libraries, or on the compilation/linking recipe to compose the final curl target library of the end user, all depending on the attacker and their target machine. Because these attacks must be extra carefully constructed for a target's software environment and surrounding network environment, middleware attacks can be highly destructive and difficult to defend against. Part of this difficulty is due to, as such is the case with curl, the problem solved by the software package necessitates extensible architecture.

Let us consider a 2-stage attack on an enterprise-like entity.


### Middleware attacks, malicious dependency injection enabled by initial phishing attack success


#### Proposed attack

Assume that some attacker finds a target with the aforementioned `without-ssl` flag enabled in the present libcurl binary. If an attacker could find a developer operations staff to be targeted for a tailored phishing message that appears legitimate, and is accepted as such by a staff member, they could cause significant damage to the targeted service but also further infect the business' network and software development environment. This message could contain a URL pointing to a malicious source of new dependency assets for software critical for business operation. Without any SSL certificate verification, the system, its maintainers or its  developers will not be able identify the fraudulent dependency until either business function is disrupted or the attackers further exploit this vulnerability. Consequently, damage caused by such an attack will vary by the attack surface that an attacker chooses to exploit. This could range from disabling a business' critical npm dependencies at a critical point of business (eg fanduel dot com during the super bowl), or an attacker could wait to exploit this vulnerability, and use malicious dependencies to disseminate malware that extracts private data.

The curl software package also includes `libcurl;` these are library functions that can be used by other applications in a given filesystem to use curl's functionality in their own execution by calling into the `libcurl` library. Curl provides configuration options for `libcurl` compilation target binary. Many of these compilation options are highly discouraged by official curl practices and channels. Such a high degree of control of the binary output from curl's compilation process gives most developers more tools that can only hurt them. If unaware of the consequences of any given configuration option, developers using curl or operations staff can open the hardware environment up to significant manipulation.

Let us consider a proposed attack on a machine using such a compiled libcurl binary.


### Memory corruption on windows with bad linking/static compilation


#### Proposed attack

Server D with active process Applet B on an open port. Applet B includes a statically compiled version of curl as the problem requires the app to include highly performant network code. Part of the networking suite included for Applet B includes some function A that calls into a static binary of libcurl's API, following this the entire binary for libcurl is copied into Server D's memory whenever function A is invoked. If an attacker is able to detect this and invoke function A in a repeatable fashion, there is significant risk for a denial of service attack on the bare-metal of the machine underlying Server D.

As pointed out in the official curl documentation maintained for curl[^5] this can be particularly damaging for businesses operating Windows servers with a statically compiled version of libcurl. Specifically, operational staff will need to configure the service to function without any DLLs interacting with static C binaries due to the following windows specific concerns.



* Windows KB article 94248[^6]


* Windows KB article 140584[^7]
Live testing was attempted to demonstrate this attack. However, we were unable to create a static curl binary that could demonstrate the mechanics of this. This is vital to highlight as it is corollary to the official curl documentation discussion regarding static compilation, "Figuring out all the dependency libraries for a given library is hard... Static compilation is not for the faint of heart"

What can be drawn from this: while the potential for exploitation may exist, this vulnerability is highly unlikely to cause damage to a business environment because it is highly unlikely that a business will statically compile curl. And even then, an attacker must become aware of this exceptional circumstance. Here, there is more security risk in the compilation options developers have than there is in the nature of the libcurl implementation.


### Conclusions Drawn

Curl's compilation and linkage pipeline can be fragile to developer manipulation, but is fairly robust from a security perspective. Each of the vulnerabilities outlined in these sections requires the configuration of curl or libcurl in such a way that is highly unlikely in a production software environment. Consequently, our view is that libcurl is fairly secure from the perspective of attacks on the compilation chain as well as from middleware injection attacks.


### Further Research

Developer advocates and communicators should continue to argue against the use of statically compiled binaries of libcurl, unless necessitated by demands of the business. Even then, this should only ever be done with extreme caution by developers with high subject matter expertise. This is especially of concern for Windows developers and operators, due to the significantly increased risk of using static libcurl binaries with Windows DLLs.

Further research can be done into weaponizing the compilation options of curl, specifically, including a fraudulent implementation of TLS to a target environment to enable some malicious goal.


## Static Analysis

We will be using a command-line application called flawfinder. A common way to use flawfinder is to first apply flawfinder to a set of source code and examine the highest- risk items. Then, use −−inputs to examine the input locations, and check to make sure that only legal and safe input values are accepted from untrusted users.


```
flawfinder src | less
```



### Level 4 Vulnerabilities

fprintf: If format strings can be influenced by an attacker, they can be exploited (CWE-134).

An attacker could add additional format specifiers to the format string like **<code>"%x %x %x"</code></strong>, which could lead to information leakage as the <strong><code>printf</code></strong> function will interpret these as format specifiers and print data from the stack. If the attacker inputs a large number of <strong><code>%x</code></strong> specifiers, they may be able to leak sensitive data like passwords, encryption keys, etc.

Even worse, the **<code>%n</code></strong> specifier can be used to write data to memory. By using <strong><code>%n</code></strong>, an attacker can write the number of characters that have been written so far to a specified memory address, potentially leading to arbitrary code execution.



* tool_cb_hdr.c:211
    * Doesn’t appear exploitable because it doesn’t manipulate a user-created string.
    * `fprintf(outs->stream, BOLD "%.*s" BOLDOFF ":", namelen, ptr);`
    * The macros BOLD and BOLDOFF here are set during compile time and there would be no way for an attacker to change it during run time.
    * The only way would be for them to change the system-defined macros on the machine where the code is recompiled.
* tool_cb_hdr.c:390
    * Same as above but with the LINK, LINKST, LINKOFF macros
* tool_cb_prg.c:206
    * The format string is made using this: `msnprintf(format, sizeof(format), "\\r%%-%ds %%5.1f%%%%", barwidth);`
    * This resolves to be a constant string with 2 format specifiers since barwidth is an integer.
    * There is no format string vulnerability.
* tool_help.c:170
    * The format string is a constant, no vulnerability.
* tool_progress.c:278
    * The format string is constant and the CURL_FORMAT_CURL_OFF_T needs to be correct during compile time.
* tool_writeout.c:157
    * The format string is constant, need to watch the CURL_FORMAT_CURL_OFF_TU macro.
* tool_writeout.c:369
    * The format string is constant, need to watch the CURL_FORMAT_CURL_OFF_T macro.

strcpy: Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120).



* tool_dirhie.c:146
    * `dirbuildup` has the same length as `outfile` and `tempdir` is a subset of `outfile` so there is not a buffer overflow that can happen.
* tool_getparam.c:648
    * The buffer `n` has a length of `outlen`. This makes overflow impossible.
* tool_main.c:123
    * This only applies in debug mode for Curl
    * The `env` buffer is trimmed down to the size of the `fname` buffer, making buffer overflow impossible.

vfprintf: If format strings can be influenced by an attacker, they can be exploited (CWE-134).



* tool_msgs.c:119
    * This function call has a `fmt` argument which is interpreted as a format string. If fmt can be influenced by an attacker, there could be an exploit. If all calls to the function are safe, then there is no vulnerability.


### Level 3 Vulnerabilities

curl_getenv: Environment variables are untrustable input if they can be set by an attacker. They can have any content and length, and the same variable can be set more than once (CWE-807, CWE-20).



* tool_findfile.c:113
    * The `home` variable is a pointer to a dynamically allocated list of command line arguments. The pointer is handled properly without use-after-free errors and buffer overflows so there is no vulnerability.

getenv: Environment variables are untrustable input if they can be set by an attacker. They can have any content and length, and the same variable can be set more than once (CWE-807, CWE-20).



* tool_operate.c:1302
    * This call is in debug code so there is no vulnerability if the program is running in production mode. Even if it were in debug mode, all variables are handled correctly so there is still no vulnerability.
* tool_vms.c:58
    * The `SHELL` variable is being accessed here and is not being handled in a way that would pose a security risk.
* tool_xattr.c:90
    * This is only for debug mode and is a specialized variable for curl debugging and does not pose a security threat.


### How Flawfinder Works

Flawfinder uses an internal database called the “ruleset”; the ruleset identifies functions that are common causes of security flaws. The standard ruleset includes a large number of different potential problems, including both general issues that can impact any C/C++ program, as well as a number of specific Unix-like and Windows functions that are especially problematic.

Flawfinder works by doing simple lexical tokenization (skipping comments and correctly tokenizing strings), looking for token matches to the database (particularly to find function calls). This means flawfinder can find vulnerabilities in programs that cannot be built or cannot be linked[^8].


### Limitations

Flawfinder does _not_ use or have access to information about control flow, data flow, or data types when searching for potential vulnerabilities or estimating the level of risk.


## Fuzz Testing

We conducted fuzz testing using AFL (American Fuzzy Lop).


### Fuzzed Names

We initially just tested 50 popular sites, and expected that curl would have no issue with them, since the sites are visited frequently. This fuzz test was done with each site curled sequentially, i.e. one input file with the 50 urls, with 1 cycle. Urls were only fuzzed in their name declaration, and total run time was about 1 hour and 20 minutes (see 
[fuzz testing results 1](#fuzz-testing-results-1) under 
[Supplementary materials](#supplementary-materials)).

Interestingly, as shown in the “overall results” section, there were 2 unique hangs. Examining the inputs that caused these hangs (see 
[hanging inputs 1](#hanging-inputs-1) and 
[hanging inputs 2](#hanging-inputs-2) under 
[Supplementary materials](#supplimentary-materials)), the common fuzz that seemed to cause the hang was the presence of “^@” in the api.ipify site. This does make sense because “^@” is represented as a null byte/zero byte. These null bytes are typically used for string manipulation, input parsing, or checking boundary conditions. Thus, it's feasible that this null byte triggered an issue in the target program, causing it to hang or become unresponsive. It’s definitely worth noting that curl is not robust against preventing hangs with certain inputs.


### Random Binary

Now we conducted another fuzz test, but also included random binary data into each curl request. Furthermore, each curl request is performed separately (not sequentially) with no duplicate URLs, and the fuzz test ran for about 4 hours and 45 minutes, for a total of 3 complete cycles (see 
[fuzz testing results 2](#fuzz-testing-results-2) under 
[Supplementary materials](#supplimentary-materials)).

The overall results indicate that there were no unique crashes or unique hangs! 


### Suspicious URLs and Random Binary

The final fuzz test we conducted was with 50 fraudulent websites according to Artists Against 419’s [fake sites list](https://db.aa419.org/fakebankslist.php?start=21)[^9]. Similarly to the last test, random binary data was also attached as inputs when curling. The idea behind testing these kinds of sites is to see what kind of crashes or hangs happen when curling to them because they are fraudulent in design.The fuzz test ran for about 6 hours, for a total of 6 full cycles done (see[ fuzz testing results 3](https://docs.google.com/document/d/11fCYAGV9lGJkXnhb2g4O1D4G6DJ68jvW-yZ-b_7p3uA/edit#heading=h.lwht19xe3irj) under[ Supplementary materials](https://docs.google.com/document/d/11fCYAGV9lGJkXnhb2g4O1D4G6DJ68jvW-yZ-b_7p3uA/edit#heading=h.jq4gzcbstdm3)).

Surprisingly, as shown in the output below, there were no unique crashes or hangs! We believe that while these sites are malicious in nature, curling to them does not lead necessarily to crashes/hangs because of the nature in how curl works. Curl makes an HTTP request to a site, and receives an HTTP response. These malicious sites we tested were not designed to be malicious in this way. Rather, they probably required a user to actually visit and interact with the site, which would then produce problems on their end. Even so, it was definitely worth investigating to see how curl would handle these kinds of sites in a fuzz test.

[This Github repository](https://github.com/mchoi574055/Fuzz-Test)[^10] contains all the testing scripts and testing inputs for all the fuzz tests conducted above.


# Recommendations for future evaluations

A major factor we neglected in our analysis is the live testing of curl compiled under its various configuration options due to its determined difficulty. These options include not only C compiler options, but also options to swap out and disable entire library backends[^11]. Curl’s extensive use of external modules is demonstrated by 
[this figure](#libcurl-backends) (“libcurl backends,” included under 
[Supplementary materials](#supplimentary-materials)) from the “Everything curl” page on the subject. Given such a wide range of possible behavior, it is very likely that there is errant behavior present in some combination of backends that we have overlooked.

As for what should prompt a fresh review of curl, we have identified several notable scenarios. First is when a new version is released or right before it is released, if possible. Since each version brings with it a slew of changes in the source code, there are many chances for vulnerabilities to have been inadvertently introduced, even as other vulnerabilities are patched. Second is when flaws are discovered by outside parties. This might indicate overarching oversights by the main development team, and may warrant extra scrutiny on both recent and past code changes. Third is when curl starts being used in unexpected ways or simply in ways notably different to how it is currently used. In these cases, curl may be intentionally forced to exhibit behavior that has not been tested or observed before. This might also include ways to abuse curl, either to perform malicious attacks with the aid of curl or on curl itself.


# Lessons learned by performing the security evaluation

From the results of the tasks we performed, we gained insight into designing secure systems, evaluating the security of systems, and secure programming.

Our design review improved our critical thinking when analyzing systems, reframing how we see those systems to consider how they might compromise their user, even when working as intended. In addition to critically analyzing each vulnerable component of curl, we also learned how to perform supplemental exercises, such as tracing data flow and drawing attack trees. 

In order to perform both fuzz testing and static analysis, we had to determine which tools would most efficiently and thoroughly complete each task, comparing those that were available in order to make such a decision. These tools ended up being AFL and flawfinder respectively, as described above. Having identified and learned how to use these tools, we can quickly deploy them in future analyses, both on curl and other similar software projects.

Static analysis and fuzz testing also revealed to us both patterns in insecure coding and common problematic inputs, which could be considered in future unit tests. These commonalities can be looked for in both security review of other projects as well as during the production of our own secure code.


# Work breakdown

Each member took responsibility for executing one task and writing its section under Results as follows:



* Previously Documented Vulnerabilities — Theodore Lau
* Design Review — Adam Murtagh
* Implications of Disabling Libraries — Sami Hamide
* Static Analysis — Alexander West
* Fuzz Testing — Michael Choi

We all took part equally in writing, revising, and proofreading the rest of the final report.


# Supplementary materials


###### fuzz testing results 1

<img width="620" alt="image" src="https://github.com/awest25/CS161/assets/93575706/d887955e-3663-44de-8607-7f0b096e7df2">


###### hanging inputs 1

<img width="622" alt="image" src="https://github.com/awest25/CS161/assets/93575706/b1f08972-adbf-4084-82ae-3c15547a90f9">

###### hanging inputs 2

<img width="622" alt="image" src="https://github.com/awest25/CS161/assets/93575706/384dd93d-dd74-4659-b0a2-6e915f4d3e68">

###### fuzz testing results 2

<img width="621" alt="image" src="https://github.com/awest25/CS161/assets/93575706/f97b677a-9123-43b7-bb26-773eb2c369c3">


###### fuzz testing results 3


<img width="622" alt="image" src="https://github.com/awest25/CS161/assets/93575706/3809a227-85bf-4480-a61b-dabb1333ea3c">



###### libcurl backends

<img width="637" alt="image" src="https://github.com/awest25/CS161/assets/93575706/c9f7a0d6-4601-4ad7-90fc-74d19c186a7c">




<!-- Footnotes themselves at the bottom. -->
## Notes

[^1]:

     [https://dwheeler.com/flawfinder/](https://dwheeler.com/flawfinder/)

[^2]:

     [https://lcamtuf.coredump.cx/afl/](https://lcamtuf.coredump.cx/afl/)

[^3]:
     [https://curl.se/docs/vuln-8.0.1.html](https://curl.se/docs/vuln-8.0.1.html)

[^4]:
     [https://hackerone.com/reports/1913733](https://hackerone.com/reports/1913733)

[^5]:
     [Curl documentation on Static building](https://curl.se/docs/install.html#static-builds)

[^6]:

     [Windows Knowledge Base 94248](https://learn.microsoft.com/en-US/troubleshoot/developer/visualstudio/cpp/libraries/use-c-run-time)

[^7]:

     [Windows Knowledge Base 140584](https://learn.microsoft.com/en-us/cpp/c-runtime-library/potential-errors-passing-crt-objects-across-dll-boundaries?view=msvc-170)

[^8]:
     [https://dwheeler.com/flawfinder/flawfinder.pdf](https://dwheeler.com/flawfinder/flawfinder.pdf)

[^9]:
     [https://db.aa419.org/fakebankslist.php?start=21](https://db.aa419.org/fakebankslist.php?start=21)

[^10]:
     [https://github.com/mchoi574055/Fuzz-Test](https://github.com/mchoi574055/Fuzz-Test)

[^11]:
     [https://everything.curl.dev/internals/backends](https://everything.curl.dev/internals/backends)
