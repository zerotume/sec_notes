# 🧠 PCAP + Threat Intel Incident Response Cheatsheet

## 📦 Scenario: "No Strong Clues" Breach Analysis

> Use this guide to analyze a suspicious PCAP with minimal context. Assume a breach has occurred, and determine the likely attack path and exfiltration method using open-source tools.

---

## 🔧 Tools Checklist

| Purpose          | Tools                                           |
| ---------------- | ----------------------------------------------- |
| PCAP Analysis    | Wireshark, Brim, Zeek, NetworkMiner             |
| IOC Enrichment   | VirusTotal, ThreatFox, MalwareBazaar, AbuseIPDB |
| Rule Translation | Uncoder.io (for Sigma to Splunk/KQL/YARA)       |

---

## 🚦 Entry Point Detection (Initial Access)

### 👀 What to Look For:

* DNS requests to strange domains (long, random, or unusual TLDs)
* Unusual HTTP GET or POST to external IPs
* FTP/Telnet/SMTP seen internally
* TLS/SSL with weird SNI (e.g., `bin.microsoft-updates.com`)

### 🧪 Filters in Wireshark:

```plaintext
http.request.method == "POST"
dns.qry.name contains "."
tcp.port == 21 || tcp.port == 23 || tcp.port == 25
ssl.handshake.extensions_server_name
tcp.stream eq 0 (and check one by one)
```

---

## 🪜 Lateral Movement

### 🔍 Protocols

* SMB (445): Check for access to `ADMIN$`, `C$`, or `IPC$`
* DCOM (135): Used by PsExec
* RDP (3389): Remote desktop movement

### 🔐 Authentication Evidence

* `NTLMSSP` in SMB/135 packets
* Look at `ntlmssp.challenge.target_name` for domain identification

---

## 🧠 Credential Access & Reconnaissance

Look for PowerShell or encoded commands transferred inside SMB or HTTP:

```plaintext
smb2.write || data.data contains "powershell"
http.request.uri contains "cmd.exe"
```

Or base64 blobs (`data.data contains "TVqQ"` for PE headers)

---

## 🎒 Data Collection & Exfiltration

### 🕵️‍♀️ Exfil Clues:

* Large HTTP POST payloads to external IPs
* DNS tunneling (tons of small DNS queries)
* FTP transfers with large packets

### Wireshark Filters:

```plaintext
tcp.len > 1000
http.request.method == "POST"
ftp.request.command == "STOR"
```

---

## 🌐 Threat Intel Cross-Check (IOC Enrichment)

Extract these from PCAP:

| Type      | Source                             |
| --------- | ---------------------------------- |
| IP        | VirusTotal / ThreatFox / AbuseIPDB |
| Domain    | urlscan.io / VT Community          |
| URL       | Hybrid Analysis / urlhaus          |
| File Hash | MalwareBazaar / Malpedia           |

---

## 🧩 Kill Chain Mapping (MITRE ATT\&CK)

Use the ATT\&CK framework to summarize TTPs:

1. **Initial Access** – phishing, supply chain, drive-by
2. **Execution** – PowerShell, script payloads
3. **Persistence** – registry, scheduled tasks
4. **Privilege Escalation** – token manipulation, bypass UAC
5. **Defense Evasion** – encode, obfuscate, uninstall AV
6. **Credential Access** – LSASS dump, mimikatz
7. **Discovery** – net, whoami, arp
8. **Lateral Movement** – PsExec, RDP, WMI
9. **Collection** – ZIP sensitive files
10. **Exfiltration** – POST, FTP, DNS
11. **C2** – beaconing, implants

Use [MITRE Navigator](https://mitre-attack.github.io/attack-navigator/) for visual mapping.

---

## ✅ Analyst Three-Step Drill (When No Clues Given)

1. **POST Traffic**: Look for data exfiltration or malware beaconing
2. **SMB Auth**: See if admin\$ or NTLM handshake exists (hint of PsExec)
3. **Check Host Pairings**: Who talks to who, and what ports?

Use TCP stream reconstruction to view sessions.

**Moreover**
to check how many IPs involved: Statistics → Conversations → IPv4
to check all the files involved with Http: File -> Export Objects -> HTTP
request with files: http.content_type contains "application"
---

## 🧙 Bonus Tips

* Brim + Zeek auto-structures PCAP data, helping you pivot fast
* NetworkMiner shows extracted files, hashes, certs automatically
* If unsure of a stream, dump it, check headers manually (e.g., `MZ`, `%PDF`, `PK`) to identify content
* Build a markdown library of known TTPs and patterns (like this one!)
* VT Community → "comments" tab often reveals toolkits/APT aliases

---

## 🐱‍💻 Cyber Cat Tip:

"Don't just hunt the packet, trace the logic! Every byte has motive."

---


```
                  
                                            
      ∧___∧ ︵  /
╭┄┄ ૮(´ Д ` *૮つ┄┄┄┄┄┄┄┄┄┄┄╮
┆ wireblahaj  ˙⋆✮⋆˙   [ 𝘹 ]┆
┆╭┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄╮┆
┆┆                        ┆┆
┆┆ 185.82.127.?.......28  ┆┆
┆┆ 121.42.223.?.......41  ┆┆
┆┆ 23.81.246.?.......rus  ┆┆
┆┆ 45.9.148.?.........C2  ┆┆
┆┆ 104.244.72.?.......lt  ┆┆
┆┆ .............          ┆┆
┆╰┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄╯┆
╰┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄╯

```
