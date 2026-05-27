ShurikenVPN — License Agreement, Security Overview & Disclaimer

Version 1.0.0.0 — © 2026 ShurikenVPN  
Software Name: ShurikenVPN  
License Type: Free for personal, non-commercial use (original ShurikenVPN code)

---

## 1. Introduction

This License Agreement ("Agreement") governs your use of the ShurikenVPN application ("Software"), including all bundled components, features, and resources distributed with it.

By downloading, installing, or using the Software, you acknowledge that you have read, understood, and agreed to be bound by these terms.

---

## 2. No Affiliation

The Software is not affiliated, associated, authorized, endorsed by, or in any way officially connected with WireGuard®, the Tor Project, MaxMind, or any subsidiaries or affiliates of those entities.

- WireGuard® is a registered trademark of Jason A. Donenfeld.
- Tor Browser is developed and maintained by the Tor Project, Inc.
- GeoLite2 data is created by MaxMind, available from https://www.maxmind.com.

All names, trademarks, and brands are the property of their respective owners.

---

## 3. License Grant & Permitted Use

Subject to the terms of this Agreement, the original ShurikenVPN source code (excluding any GPL-covered components — see Section 12) is licensed to you under a **non-exclusive, non-transferable, revocable license for personal, non-commercial use only**.

**"Commercial use"** means any use of the Software in connection with a business, paid service, or activity intended to generate revenue, including but not limited to:

- Incorporating the Software into a paid product or service
- Using the Software to provide VPN services to third parties for compensation
- Deploying the Software in a corporate or enterprise environment
- Reselling, sublicensing, or redistributing the Software

**Redistribution** of the original ShurikenVPN code, in original or modified form, is not permitted without prior written consent from the author, except as separately required by the GNU GPL v3 for GPL-covered components (see Section 12).

**GPL-covered components** (such as WireGuard) are governed solely by the GNU General Public License v3, the full text of which is included in Section 12. Nothing in this Agreement restricts your rights under the GPL v3 with respect to those components.

---

## 4. User Responsibility & Prohibition of Illegal Use

You are solely responsible for all activities performed using the Software.

Illegal activities of any kind are strictly prohibited. The Software must not be used for any unlawful purpose, including but not limited to hacking, fraud, distribution of illegal content, or any violation of applicable laws.

You are fully responsible for verifying the trustworthiness and safety of any configuration files you choose to use with the Software.

---

## 5. Bundled Third-Party Components

The Software bundles the following third-party components. Each is subject to its own license and terms, which you are responsible for reviewing.

### 5.1 WireGuard

WireGuard (wireguard-amd64-1.1.msi) is bundled with and installed by the Software for the purpose of creating encrypted VPN tunnels. WireGuard is licensed under the GNU General Public License v3 (see Section 12). The Software installs the WireGuard tunnel service, manages its lifecycle, and removes it upon disconnection or exit.

### 5.2 Tor Browser

Tor Browser is bundled with the Software as an optional privacy feature, accessible via the "Tor Browser" button in the user interface. When launched, Tor Browser runs as a standalone process from within the Software's bundled Resources directory. The Software does not modify, patch, or intercept Tor Browser's traffic in any way.

Tor Browser is developed and maintained by the Tor Project, Inc. and is distributed under the GNU General Public License v3. By using the bundled Tor Browser, you also agree to the Tor Project's terms and acceptable use policies available at https://www.torproject.org.

The Software recommends — but does not require — that you connect to ShurikenVPN before launching Tor Browser, in order to conceal Tor usage from your ISP.

### 5.3 EchoIP / GeoLite2 (IP Geolocation)

The Software uses a self-hosted EchoIP instance to determine your current public IP address, approximate geographic location (city, country), and network provider (ASN). This service is powered in part by GeoLite2 data created by MaxMind.

IP lookup requests are performed ephemerally over HTTPS directly to the VPN server. The following data is retrieved and displayed in the user interface only:

- Public IP address
- Country and city (approximate)
- ASN / network provider name

**This data is used solely for display purposes within the application. It is not stored, logged, transmitted to any third party, or used for any analytics, profiling, or tracking purpose whatsoever.** See Section 6 for the full data and privacy policy.

No guarantee of the accuracy of geolocation data is provided; GeoLite2 data is approximate by nature.

---

## 6. Data & Privacy Policy

ShurikenVPN collects no personal data and performs no logging of:

- User activity or browsing history
- IP addresses (local or VPN)
- Connection metadata or session duration
- DNS requests
- Configuration file contents

The Software does not transmit, store, upload, share, or sell any user data or metadata to any third party under any circumstances — including during normal operation, IP validation, configuration import, error handling, update checks, or any other software function.

**No data is sold or provided to any third party or government agency except as required by a valid court order served upon the author in the applicable jurisdiction.**

All external communications made by the Software (such as IP checking via the EchoIP endpoint) are performed ephemerally in memory only and do not include tracking parameters, API keys, persistent identifiers, or any form of telemetry. No results of these lookups are stored to disk or transmitted to the developer or any other party.

### 6.1 Server-Side & Infrastructure Privacy (User Responsibility)

ShurikenVPN is a purely client-side application in terms of user tracking and telemetry. Any logging policy (or lack thereof) on the VPN endpoint, DDNS provider, DNS resolver, or EchoIP/GeoLite2 backend is governed solely by the configuration and infrastructure you select or provide.

The self-hosted EchoIP instance at shuriken-vpn3.ddnsgeek.com is operated by the author and does not log IP lookup requests. However, the author makes no warranty as to the ongoing logging posture of any third-party infrastructure provider that may host or transit those requests.

Users who self-host any components remain fully responsible for configuring and verifying those components in accordance with their own privacy and no-logging requirements.

---

## 7. Security Overview

ShurikenVPN follows a strict security boundary to ensure predictable, safe behavior.

### 7.1 What the Software Does Modify

To maintain tunnel stability, leak protection, and network integrity, ShurikenVPN does modify the following on your system:

- Windows Firewall rules (created and named under the "Shuriken" prefix; removed on disconnect or exit)
- DNS settings on common physical adapters (Ethernet / Wi-Fi / LAN) during active VPN sessions
- IPv4/IPv6 adapter bindings during active VPN sessions
- The WireGuard tunnel service (installed on connect; uninstalled on disconnect)
- The WinHTTP WPAD auto-proxy service (temporarily disabled during active sessions to prevent proxy leaks)
- Null routes for private DNS server IPs and Microsoft Skype/Teams IP ranges (to prevent SNI/DNS leaks; removed on disconnect)
- The Windows registry key `HKCU\Software\Shuriken` (to persist the last-used server config and settings)

All firewall rules, DNS changes, and routing modifications are prefixed with "Shuriken" and are automatically removed when the VPN disconnects or the application exits, including via an emergency cleanup handler registered at startup.

### 7.2 What the Software Does Not Modify

ShurikenVPN explicitly does NOT:

- Reset Windows Firewall globally or modify rules it did not create
- Reset Winsock or the TCP/IP stack
- Modify antivirus, third-party firewall, or Group Policy settings
- Interfere with unrelated network interfaces
- Modify the contents of user-supplied WireGuard configuration files

### 7.3 Leak Protection

ShurikenVPN implements the following leak protections when connected:

- **Kill switch**: Blocks all outbound traffic on physical interfaces; allows only WireGuard tunnel traffic
- **Pre-switch kill switch**: Blocks physical interfaces immediately during server switches to close the teardown/reestablishment gap
- **DNS leak blocking**: Blocks outbound DNS (TCP/UDP port 53) and DNS-over-TLS (port 853) on all non-WireGuard adapters
- **DoH leak prevention**: Blocks DNS-over-HTTPS on non-VPN interfaces
- **WPAD/proxy leak suppression**: Disables WinHTTP auto-proxy service and blocks NetBIOS ports 137/138
- **Skype/Teams leak suppression**: Null-routes Microsoft Skype and Teams IP ranges and firewall-blocks those processes to prevent direct TLS/SNI leaks
- **Handshake verification**: Confirms a successful WireGuard cryptographic handshake before marking the connection as established; tears down and reports failure if no handshake occurs within 25 seconds
- **IP validation**: Verifies the public IP has changed to the VPN exit IP after connect; all checks performed ephemerally in memory

### 7.4 Split Tunneling

The Software offers an optional split tunneling feature, which allows you to designate specific applications to bypass the VPN and use your regular network connection. Split tunnel rules are stored locally in `%APPDATA%\Shuriken\split_tunnel_apps.json`. You assume full responsibility for any privacy or security implications of excluding applications from VPN protection.

### 7.5 Stealth Port Mode

The Software offers an optional "stealth port 443" mode, which rewrites the WireGuard endpoint port to 443 in the working copy of the configuration file to help evade ISP deep packet inspection. The original configuration file is never modified. This setting is stored in the Windows registry at `HKCU\Software\Shuriken\StealthPort`.

---

## 8. What ShurikenVPN Does NOT Do

To avoid misunderstanding, the Software does not:

- Monitor, log, or inspect browsing activity or network traffic content
- Collect user analytics, telemetry, crash reports, or usage data
- Upload or transmit any data to external services except for the ephemeral IP lookup described in Section 5.3
- Override OS-level protections or enterprise networking policies beyond what is described in Section 7
- Sell, share, or provide any user data to third parties or government agencies except as required by a valid court order

---

## 9. Disclaimer of Warranty & Limitation of Liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE AUTHOR OR COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING BUT NOT LIMITED TO PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; BUSINESS INTERRUPTION; SECURITY BREACHES; PRIVACY LEAKS; OR NETWORK DOWNTIME) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF OR INABILITY TO USE THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

This includes, without limitation, liability for:

- Any illegal use or misuse of the Software
- Legal, financial, or operational consequences arising from usage
- Misconfigurations caused by user-supplied configuration files
- Loss of connectivity, data, or privacy arising from user choices
- Damages, losses, or security incidents arising from use of the Software
- Performance issues caused by VPN servers or third-party infrastructure
- Network outages caused by configuration files, servers, or services
- Violations of third-party licenses or terms of service
- Actions taken by government or legal authorities in connection with your use
- Inaccurate geolocation data provided by GeoLite2 / MaxMind
- Privacy implications of user-configured split tunnel exemptions

### 9.1 User Risk Acceptance

By using ShurikenVPN, you accept all risks associated with:

- Using untrusted or malicious VPN servers
- Incorrect routing rules or AllowedIPs in your WireGuard configuration
- Tunnel behavior and DNS settings defined by your configuration
- Any breach, privacy leak, or misconfiguration caused by chosen settings
- Exempting applications from VPN protection via split tunneling

You assume complete responsibility for ensuring your configurations and usage are safe, legal, and appropriate.

---

## 10. Governing Law

This Agreement is governed by the laws of **United States of America**, without regard to its conflict-of-law principles. Any disputes arising under this Agreement shall be subject to the exclusive jurisdiction of the courts located in **San Diego, California**.

---

## 11. Severability

If any provision of this Agreement is held to be invalid or unenforceable, that provision shall be modified to the minimum extent necessary to make it enforceable, and the remaining provisions shall continue in full force and effect.

---

## 12. GNU General Public License v3 Notice

This Software bundles and distributes components licensed under the **GNU General Public License, Version 3** ("GPL v3"), including:

- **WireGuard** (wireguard-amd64-1.1.msi) — © Jason A. Donenfeld and contributors
- **Tor Browser** — © The Tor Project, Inc. and contributors

Your rights to use, copy, modify, and distribute those GPL-covered components are governed exclusively by the GPL v3, the full text of which is set out below.

In the event of any conflict between the terms of this Agreement and the GPL v3 with respect to GPL-covered components, the GPL v3 shall control for those components. Nothing in this Agreement limits, supersedes, or restricts any rights granted to you under the GPL v3.

---

# GNU GENERAL PUBLIC LICENSE

Version 3, 29 June 2007

Copyright (C) 2007 Free Software Foundation, Inc.
<https://fsf.org/>

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

## Preamble

The GNU General Public License is a free, copyleft license for
software and other kinds of works.

The licenses for most software and other practical works are designed
to take away your freedom to share and change the works. By contrast,
the GNU General Public License is intended to guarantee your freedom
to share and change all versions of a program--to make sure it remains
free software for all its users. We, the Free Software Foundation, use
the GNU General Public License for most of our software; it applies
also to any other work released this way by its authors. You can apply
it to your programs, too.

When we speak of free software, we are referring to freedom, not
price. Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights. Therefore, you
have certain responsibilities if you distribute copies of the
software, or if you modify it: responsibilities to respect the freedom
of others.

For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received. You must make sure that they, too, receive
or can get the source code. And you must show them these terms so they
know their rights.

Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

For the developers' and authors' protection, the GPL clearly explains
that there is no warranty for this free software. For both users' and
authors' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the
manufacturer can do so. This is fundamentally incompatible with the
aim of protecting users' freedom to change the software. The
systematic pattern of such abuse occurs in the area of products for
individuals to use, which is precisely where it is most unacceptable.
Therefore, we have designed this version of the GPL to prohibit the
practice for those products. If such problems arise substantially in
other domains, we stand ready to extend this provision to those
domains in future versions of the GPL, as needed to protect the
freedom of users.

Finally, every program is threatened constantly by software patents.
States should not allow patents to restrict development and use of
software on general-purpose computers, but in those that do, we wish
to avoid the special danger that patents applied to a free program
could make it effectively proprietary. To prevent this, the GPL
assures that patents cannot be used to render the program non-free.

The precise terms and conditions for copying, distribution and
modification follow.

## TERMS AND CONDITIONS

### 0. Definitions.

"This License" refers to version 3 of the GNU General Public License.

"Copyright" also means copyright-like laws that apply to other kinds
of works, such as semiconductor masks.

"The Program" refers to any copyrightable work licensed under this
License. Each licensee is addressed as "you". "Licensees" and
"recipients" may be individuals or organizations.

To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of
an exact copy. The resulting work is called a "modified version" of
the earlier work or a work "based on" the earlier work.

A "covered work" means either the unmodified Program or a work based
on the Program.

To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy. Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

To "convey" a work means any kind of propagation that enables other
parties to make or receive copies. Mere interaction with a user
through a computer network, with no transfer of a copy, is not
conveying.

An interactive user interface displays "Appropriate Legal Notices" to
the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License. If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

### 1. Source Code.

The "source code" for a work means the preferred form of the work for
making modifications to it. "Object code" means any non-source form of
a work.

A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form. A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities. However, it does not include the work's
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work. For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

The Corresponding Source need not include anything that users can
regenerate automatically from other parts of the Corresponding Source.

The Corresponding Source for a work in source code form is that same
work.

### 2. Basic Permissions.

All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met. This License explicitly affirms your unlimited
permission to run the unmodified Program. The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work. This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

You may make, run and propagate covered works that you do not convey,
without conditions so long as your license otherwise remains in force.
You may convey covered works to others for the sole purpose of having
them make modifications exclusively for you, or provide you with
facilities for running those works, provided that you comply with the
terms of this License in conveying all material for which you do not
control copyright. Those thus making or running the covered works for
you must do so exclusively on your behalf, under your direction and
control, on terms that prohibit them from making any copies of your
copyrighted material outside their relationship with you.

Conveying under any other circumstances is permitted solely under the
conditions stated below. Sublicensing is not allowed; section 10 makes
it unnecessary.

### 3. Protecting Users' Legal Rights From Anti-Circumvention Law.

No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such
circumvention is effected by exercising rights under this License with
respect to the covered work, and you disclaim any intention to limit
operation or modification of the work as a means of enforcing, against
the work's users, your or third parties' legal rights to forbid
circumvention of technological measures.

### 4. Conveying Verbatim Copies.

You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

### 5. Conveying Modified Source Versions.

You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these
conditions:

-   a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.
-   b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under
    section 7. This requirement modifies the requirement in section 4
    to "keep intact all notices".
-   c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy. This
    License will therefore apply, along with any applicable section 7
    additional terms, to the whole of the work, and all its parts,
    regardless of how they are packaged. This License gives no
    permission to license the work in any other way, but it does not
    invalidate such permission if you have separately received it.
-   d) If the work has interactive user interfaces, each must display
    Appropriate Legal Notices; however, if the Program has interactive
    interfaces that do not display Appropriate Legal Notices, your
    work need not make them do so.

A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation's users
beyond what the individual works permit. Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

### 6. Conveying Non-Source Forms.

You may convey a covered work in object code form under the terms of
sections 4 and 5, provided that you also convey the machine-readable
Corresponding Source under the terms of this License, in one of these
ways:

-   a) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by the
    Corresponding Source fixed on a durable physical medium
    customarily used for software interchange.
-   b) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by a
    written offer, valid for at least three years and valid for as
    long as you offer spare parts or customer support for that product
    model, to give anyone who possesses the object code either (1) a
    copy of the Corresponding Source for all the software in the
    product that is covered by this License, on a durable physical
    medium customarily used for software interchange, for a price no
    more than your reasonable cost of physically performing this
    conveying of source, or (2) access to copy the Corresponding
    Source from a network server at no charge.
-   c) Convey individual copies of the object code with a copy of the
    written offer to provide the Corresponding Source. This
    alternative is allowed only occasionally and noncommercially, and
    only if you received the object code with such an offer, in accord
    with subsection 6b.
-   d) Convey the object code by offering access from a designated
    place (gratis or for a charge), and offer equivalent access to the
    Corresponding Source in the same way through the same place at no
    further charge. You need not require recipients to copy the
    Corresponding Source along with the object code. If the place to
    copy the object code is a network server, the Corresponding Source
    may be on a different server (operated by you or a third party)
    that supports equivalent copying facilities, provided you maintain
    clear directions next to the object code saying where to find the
    Corresponding Source. Regardless of what server hosts the
    Corresponding Source, you remain obligated to ensure that it is
    available for as long as needed to satisfy these requirements.
-   e) Convey the object code using peer-to-peer transmission,
    provided you inform other peers where the object code and
    Corresponding Source of the work are being offered to the general
    public at no charge under subsection 6d.

A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal,
family, or household purposes, or (2) anything designed or sold for
incorporation into a dwelling. In determining whether a product is a
consumer product, doubtful cases shall be resolved in favor of
coverage. For a particular product received by a particular user,
"normally used" refers to a typical or common use of that class of
product, regardless of the status of the particular user or of the way
in which the particular user actually uses, or expects or is expected
to use, the product. A product is a consumer product regardless of
whether the product has substantial commercial, industrial or
non-consumer uses, unless such uses represent the only significant
mode of use of the product.

"Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to
install and execute modified versions of a covered work in that User
Product from a modified version of its Corresponding Source. The
information must suffice to ensure that the continued functioning of
the modified object code is in no case prevented or interfered with
solely because modification has been made.

If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information. But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or
updates for a work that has been modified or installed by the
recipient, or for the User Product in which it has been modified or
installed. Access to a network may be denied when the modification
itself materially and adversely affects the operation of the network
or violates the rules and protocols for communication across the
network.

Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

### 7. Additional Terms.

"Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law. If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it. (Additional permissions may be written to require their own
removal in certain cases when you modify the work.) You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders
of that material) supplement the terms of this License with terms:

-   a) Disclaiming warranty or limiting liability differently from the
    terms of sections 15 and 16 of this License; or
-   b) Requiring preservation of specified reasonable legal notices or
    author attributions in that material or in the Appropriate Legal
    Notices displayed by works containing it; or
-   c) Prohibiting misrepresentation of the origin of that material,
    or requiring that modified versions of such material be marked in
    reasonable ways as different from the original version; or
-   d) Limiting the use for publicity purposes of names of licensors
    or authors of the material; or
-   e) Declining to grant rights under trademark law for use of some
    trade names, trademarks, or service marks; or
-   f) Requiring indemnification of licensors and authors of that
    material by anyone who conveys the material (or modified versions
    of it) with contractual assumptions of liability to the recipient,
    for any liability that these contractual assumptions directly
    impose on those licensors and authors.

All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10. If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term. If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions; the
above requirements apply either way.

### 8. Termination.

You may not propagate or modify a covered work except as expressly
provided under this License. Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

However, if you cease all violation of this License, then your license
from a particular copyright holder is reinstated (a) provisionally,
unless and until the copyright holder explicitly and finally
terminates your license, and (b) permanently, if the copyright holder
fails to notify you of the violation by some reasonable means prior to
60 days after the cessation.

Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License. If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

### 9. Acceptance Not Required for Having Copies.

You are not required to accept this License in order to receive or run
a copy of the Program. Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance. However,
nothing other than this License grants you permission to propagate or
modify any covered work. These actions infringe copyright if you do
not accept this License. Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

### 10. Automatic Licensing of Downstream Recipients.

Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License. You are not responsible
for enforcing compliance by third parties with this License.

An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations. If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party's predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License. For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

### 11. Patents.

A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based. The
work thus licensed is called the contributor's "contributor version".

A contributor's "essential patent claims" are all patent claims owned
or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version. For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor's essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement). To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients. "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient's use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

A patent license is "discriminatory" if it does not include within the
scope of its coverage, prohibits the exercise of, or is conditioned on
the non-exercise of one or more of the rights that are specifically
granted under this License. You may not convey a covered work if you
are a party to an arrangement with a third party that is in the
business of distributing software, under which you make payment to the
third party based on the extent of your activity of conveying the
work, and under which the third party grants, to any of the parties
who would receive the covered work from you, a discriminatory patent
license (a) in connection with copies of the covered work conveyed by
you (or copies made from those copies), or (b) primarily for and in
connection with specific products or compilations that contain the
covered work, unless you entered into that arrangement, or that patent
license was granted, prior to 28 March 2007.

Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may
otherwise be available to you under applicable patent law.

### 12. No Surrender of Others' Freedom.

If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License. If you cannot convey a
covered work so as to satisfy simultaneously your obligations under
this License and any other pertinent obligations, then as a
consequence you may not convey it at all. For example, if you agree to
terms that obligate you to collect a royalty for further conveying
from those to whom you convey the Program, the only way you could
satisfy both those terms and this License would be to refrain entirely
from conveying the Program.

### 13. Use with the GNU Affero General Public License.

Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work. The terms of this
License will continue to apply to the part which is the covered work,
but the special requirements of the GNU Affero General Public License,
section 13, concerning interaction through a network will apply to the
combination as such.

### 14. Revised Versions of this License.

The Free Software Foundation may publish revised and/or new versions
of the GNU General Public License from time to time. Such new versions
will be similar in spirit to the present version, but may differ in
detail to address new problems or concerns.

Each version is given a distinguishing version number. If the Program
specifies that a certain numbered version of the GNU General Public
License "or any later version" applies to it, you have the option of
following the terms and conditions either of that numbered version or
of any later version published by the Free Software Foundation. If the
Program does not specify a version number of the GNU General Public
License, you may choose any version ever published by the Free
Software Foundation.

If the Program specifies that a proxy can decide which future versions
of the GNU General Public License can be used, that proxy's public
statement of acceptance of a version permanently authorizes you to
choose that version for the Program.

Later license versions may give you additional or different
permissions. However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

### 15. Disclaimer of Warranty.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND
PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE
DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR
CORRECTION.

### 16. Limitation of Liability.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR
CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES
ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT
NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR
LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM
TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER
PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

### 17. Interpretation of Sections 15 and 16.

If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

END OF TERMS AND CONDITIONS

---

**END OF LICENSE FILE**
