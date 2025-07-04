# 🔐 Blue Team Network Protocol & Log Analysis Cheatsheet

A field cheat sheet for identifying attacker behavior through PCAPs, logs, and other data during threat hunting, DFIR, or CTFs.

---

## 🧠 Protocol Quick Recognition

| Protocol  | Common Ports | Typical Use / Clues | Suspicious Signs |
|-----------|--------------|---------------------|------------------|
| **SMB**   | 445 / 139     | File sharing, NTLM auth, PsExec | NTLMSSP target names, `IPC$`, `admin$`, long sessions |
| **RPC**   | 135           | PsExec, WMI, DCOM   | UUID mapping, exec from remote host |
| **Kerberos** | 88         | Auth in AD env      | Ticket-granting service, `krbtgt`, golden ticket |
| **LDAP**  | 389 / 636     | Directory queries    | User, computer enumeration |
| **DNS**   | 53            | Domain resolution    | DGA domains, large TXT responses |
| **HTTP/HTTPS** | 80/443   | Browsing, malware C2 | Suspicious User-Agent, beaconing, encoded params |
| **ICMP**  | 0, 8, 11      | Ping, traceroute     | Unexpected tunnels (`icmp-tunnel`) |
| **RDP**   | 3389          | Remote access        | Sudden new connection, lateral movement |
| **FTP**   | 21            | File transfer        | Cleartext creds, unrecognized uploads |
| **DHCP**  | 67/68         | IP lease requests    | Rogue DHCP server, abnormal assignments |
| **mDNS**  | 5353          | Local network discovery | Unexpected broadcast storm |
| **NBNS**  | 137           | NetBIOS name queries | Responder poisoning |
| **LLMNR** | 5355          | Name resolution fallback | Responder poisoning |
| **Sysmon**| Logs only     | Host-based events    | Process creation, pipe connection, driver load |

---

## 🔎 NTLM-related Indicators

| Field | Use |
|-------|-----|
| `ntlmssp.challenge.target_name` | Indicates target hostname/domain |
| `ntlmssp.authenticate.user`    | Credential capture / impersonation |
| `ntlmssp.negotiate.flags`      | Encryption capability / fallback |
| `ntlmssp.version`              | OS version of client |

### 👉 When to Look:
- SMB over port 445
- PsExec or lateral movement
- Windows auth mechanisms

---

## 📊 PCAP Hunting Tips

### Wireshark Display Filters

- `tcp.port == 445` → SMB
- `smb2` → All SMB2+ packets
- `ntlmssp` → Show NTLM authentication
- `kerberos` → Look for `krbtgt`, forged tickets
- `http.request.uri contains "cmd"` → Look for command execution in URIs
- `frame contains "Mimikatz"` → Keyword detection

---

## 🧰 Useful Tools & Use Cases

| Tool            | Use Case |
|-----------------|----------|
| **Wireshark**   | Deep PCAP analysis |
| **Brim / Zeek** | Large PCAP summary |
| **Sysmon + Logstash** | Host-level event analysis |
| **Kibana / Splunk**   | SIEM / threat hunting |
| **CyberChef**   | Decoding obfuscated payloads |
| **ALEAPP**      | Android forensic artifact parser |
| **Volatility**  | Memory forensic framework |

---

## 🧩 Suspicious SMB Behavior Patterns

- `Tree Connect Request` to `\\hostname\IPC$` — PsExec prep
- `Create Request` to `\\hostname\ADMIN$` — file copy to remote admin share
- `Write AndX` or `NT Create AndX` with long payloads — file transfer
- NTLMSSP with usernames not in current domain

---

## 🔥 Event ID Highlights (Windows)

| Event ID | Description |
|----------|-------------|
| 4624     | Successful login |
| 4625     | Failed login |
| 4688     | Process creation |
| 4776     | NTLM authentication |
| 4768     | Kerberos TGT request |
| 4769     | Kerberos service ticket |
| 7045     | New service created |
| 1102     | Audit log cleared (TAMPERING!) |

---

## 🧬 MITRE ATT&CK Mapping (Sample)

| Tactic      | Technique | Indicators |
|-------------|-----------|------------|
| Lateral Movement | T1021.002 | SMB, PsExec, RDP |
| Credential Access | T1550.002 | Pass-the-Hash, NTLM logs |
| Discovery         | T1018     | LDAP enumeration |
| Collection        | T1005     | File access via SMB |
| Execution         | T1059     | Remote code via WMI/PsExec |

---

## 🛠️ Practice Mindset 

1. **You see the protocal? Try to get their intention asap.**  
   e.g., port 445 + `IPC$` + NTLM → Lateral Movement

2. **maybe I need to continue writing recaps ... to remember a new pattern everytime I'm playing with a pcap**  
   As per ChatGPT, making mistakes is the fastest way for me to be a specialist
   (as soon as I'm not bug-oriented programming...)

3. **try querying every field**  
   E.g., querying "ntlmssp.target_name usage" is definitely faster than reading them one by one ...
   (and more friendly to my eyes.)

4. **Tools! Remember to try more tools!** 
   **(Righteous feline is not born (very?) differently from others but having a knack of exploiting things to meow's advantage *cough）**  
   - Wireshark：Track the details  
   - Zeek：Extracting they key figures
   - CyberChef：Superspeed (hopefully) decoding
   - ChatGPT：Almost became my cyber girlfriend (???)

---

       ____
      /    \  ~🎵
    (／＞)(フ)   
    | ヽ◉ ◉|   
   ／` ミ＿xノ 
  /　　　　 | 
 /　 ヽ　　 ﾉ   
│　　|　|　|
／￣|　　 |　|       
(￣ヽ＿_ヽ_)__)  
＼二つ             
  .------------.
 / [][][][][][] \
|[][][][][][][][]|
\[][][][][][][][]/
 \______________/

