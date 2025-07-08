## 🎯 Threat Intelligence Terminology Cheat Sheet

### 🔹 TTP: Tactics, Techniques, and Procedures

**TTP** describes the behavior and methodology used by attackers. This model helps analysts break down and classify adversary actions:

| Term         | Meaning                                        | Example |
|--------------|------------------------------------------------|---------|
| **Tactics**     | The high-level *goal* or *stage* of the attack (why) | Persistence, Lateral Movement |
| **Techniques**  | The *method* used to accomplish a tactic (how)       | PsExec, WMI, DLL Sideloading |
| **Procedures**  | The *specific implementation* of the technique       | APT28 using PsExec + WMI with hardcoded creds |

> 📌 Reference: [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

### 🔹 APT Group: Advanced Persistent Threat

APT groups are **sophisticated, well-funded threat actors**, often tied to nation-states. Characteristics:

- Long-term infiltration and persistence
- Use of custom or semi-custom malware
- Known patterns of behavior (TTPs)
- Frequently tracked by security vendors and MITRE

| APT Name     | Alleged Origin | Notable Tactics     |
|--------------|----------------|---------------------|
| APT28 (Fancy Bear) | Russia         | Credential dumping, DDoS |
| APT41              | China          | Supply chain attacks     |
| Lazarus Group      | North Korea    | Financial theft, ransomware |
| MuddyWater         | Iran           | Spear phishing, RAT deployment |

> 🔍 Tip: Use **ATT&CK Navigator** or vendor threat intel reports to map TTPs to APTs.

---

### 🔹 IOC: Indicator of Compromise

Artifacts or data points that suggest an intrusion or malicious activity.

| IOC Type       | Example                         |
|----------------|---------------------------------|
| IP Address     | 45.129.200.16                   |
| Domain         | example.evil[.]com              |
| File Hash      | 84a3bdf20398a888...             |
| File Name      | ffmpeg.dll, rundll32.exe        |
| Mutex/String   | `Global\A38C9E9B`               |

---

### 🔹 Threat Intelligence Tools

| Tool           | Use Case                                     |
|----------------|----------------------------------------------|
| **VirusTotal**     | File, hash, domain/IP enrichment              |
| **Hybrid Analysis**| Dynamic behavior + MITRE tag mapping         |
| **ThreatFox**       | Community-driven IOC database (by Abuse.ch) |
| **MalwareBazaar**   | Sample search & hash lookup (by Abuse.ch)   |
| **Uncoder.io**      | Sigma/ATT&CK/ELK rule builder (limited access) |
| **ATT&CK Navigator**| Visualize and correlate TTPs with APT groups |

---

### 🧠 Analysis Tip

> **"Group behavior is more reliable than tool names."**  
Malware can be reused, renamed, or disguised — but attacker **behavior patterns (TTPs)** tend to persist.

---

### 📎 Use Case Example

- You observe SMB + `admin$` + PsExec in logs  
→ Map it to `Lateral Movement` → MITRE Technique ID: `T1569.002`  
→ Check which APT groups use it  
→ Filter via VirusTotal/ThreatFox → Get malware family → Possibly match an APT

---

### 🐾 Bonus: Terms You Might Encounter

| Term              | Meaning                                        |
|-------------------|------------------------------------------------|
| **LOLBins**        | Living-off-the-land binaries (native tools used for bad) |
| **Beaconing**      | Repeated callback to a C2 server               |
| **YARA Rules**     | Pattern-based rules to detect malware         |
| **C2 / C&C**       | Command and Control server                     |
| **OPSEC**          | Operational security / stealth tactics        |
| **EXFIL**          | Exfiltration of data from target               |
| **Pivoting**       | Using one compromised system to move laterally |

---



```

                 へ  A      ............
               ૮  •  •)       
                /  ⁻  ៸        
            乀 (ˍ, ل📕     

```