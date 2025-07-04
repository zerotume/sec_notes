# 🧾 Blue Team Wireshark Protocol Field Cheat Sheet

_Last updated: 2025-07-04_

## 📦 Protocol → Fields → Extractable Information

| Protocol (Port)   | Packet Type / Layer     | Key Fields                             | Extracted Info                          |
|-------------------|--------------------------|-----------------------------------------|------------------------------------------|
| **SMB (445)**     | NTLMSSP_AUTH             | `User Name`, `Domain`, `Host Name`     | Who is logging into what                |
|                   | NTLMSSP_CHALLENGE        | `Target Name`                          | Target machine name                     |
|                   | Tree Connect             | `Share Name`, `IPC$`                   | Remote share access                     |
|                   | Create Request           | `File Name`                            | File or path accessed                   |
| **LDAP (389)**    | BindRequest / Response   | `name`                                 | User / domain info                      |
|                   | SearchRequest            | `baseObject`, `filter`                 | What was searched                       |
| **Kerberos (88)** | AS-REQ, AS-REP           | `client name`, `realm`                 | User and domain                         |
|                   | TGS-REQ, TGS-REP         | `service name`, `ticket`               | Requested service                       |
| **RDP (3389)**    | Cookie                   | `mstshash=USERNAME`                    | RDP username                            |
| **WinRM (5985)**  | HTTP Header              | `Authorization: NTLM ...`              | Base64 NTLM token info                  |
| **DNS (53)**      | Standard Query           | `Name`                                 | Hostnames being queried                 |
| **HTTP(S)**       | Request                  | `User-Agent`, `Host`, `Cookie`         | Browser, domain, session info           |

---

## 🎯 Common Tool Behaviors

| Tool / Technique       | Protocols          | Indicators / Fields                    |
|------------------------|--------------------|----------------------------------------|
| PsExec                 | SMB (445), NTLM    | `NTLMSSP`, `IPC$`, service pipe names  |
| Mimikatz               | Kerberos, LSASS    | `AS-REQ` without pre-auth              |
| Pass-the-Hash          | SMB / WinRM        | NTLMSSP_AUTH without Kerberos ticket   |
| RDP lateral movement   | TCP/3389           | RDP cookie / cert negotiation          |
| Cobalt Strike (Beacon) | SMB                | Obfuscated SMB payloads                |

---

## 🛡️ Wireshark Display Filters

```wireshark
# Find NTLMSSP packets
ntlmssp

# SMB file access
smb2.filename contains ".exe"
smb2.cmd == 0x05  # Tree Connect
smb2.cmd == 0x06  # Create

# RDP username
tcp.port == 3389 and rdp.cookie

# HTTP POST
http.request.method == "POST"

# DNS query names
dns.qry.name

# Kerberos identity requests
kerberos.CNameString
```

---

## 🧠 Learning Tip

Build "reflex memory" through:
- Packet hunting exercises
- Repeating display filter drills
- Creating your own "trigger maps" of protocol → intent

Want a printable PDF or editable version? Just ask!
