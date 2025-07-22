# 🧪 Wireshark Export Objects Cheatsheet

Quickly identify suspicious files in PCAPs using Wireshark’s `Export Objects` feature.

---

## 📁 Step-by-Step: Export HTTP Objects

1. Open PCAP in **Wireshark**
2. Go to `File` → `Export Objects` → `HTTP`
3. A window appears showing all HTTP file transfers:
   - 🧾 File name (from URI)
   - 📄 MIME type
   - 📦 File size
   - 💾 Download button

---

## 🎯 What to Look For

| Indicator | Description |
|----------|-------------|
| `application/octet-stream` | Possibly a binary (EXE, DLL, shellcode) |
| `.php`, `.asp`, `.jsp` | Script extension, but may be disguised payloads |
| Unusual large `.png`, `.docx`, `.pdf` | May hide malware (e.g., steganography or embedded dropper) |
| File names like `img001.php`, `icon.jpg.exe` | Classic social engineering tricks |
| `text/html` with JS or encoded content | Obfuscated scripts or redirectors |

---

## 🔍 Examples

### 🐚 Web Shell Upload

```
POST /upload.php
Content-Type: multipart/form-data
Filename: cmd.php
```

> File extracted is actually a reverse shell

---

### 🦠 Suspicious Download

```
GET /image.php?id=12345
Content-Type: application/octet-stream
```

> `image.php` drops a binary, not an image

---

### 📊 C2 Traffic via HTTP

```
GET /style.css
Content-Type: text/plain
```

> Repeated requests with changing payloads — beaconing or exfiltration

---

## 🧠 Bonus: Export from Other Protocols

| Protocol | How to Export |
|---------|----------------|
| SMB     | `File → Export Objects → SMB` |
| FTP     | `File → Export Objects → FTP` |
| TFTP    | Same as above |
| TCP     | Use `Follow TCP Stream` to inspect payload |

---

## 💡 Tips

- If unsure, export suspicious files and analyze with:
  - [VirusTotal](https://www.virustotal.com/)
  - [Hybrid Analysis](https://www.hybrid-analysis.com/)
  - `strings`, `file`, or `hexdump` in terminal
- Use `tcp.stream eq X` to locate the original transfer conversation
- Enable MIME column: `View → Packet Details Columns → Add Content-Type`

---
```
 ∧,,,,,,∧
(  ̳• · ̳• )
/       づ☕︎
```