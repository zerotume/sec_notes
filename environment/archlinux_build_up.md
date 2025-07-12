## 🛡️ Secure Malware Analysis Environment (Linux / Arch + VSCode)

### 1. ⚠️ Prevent Code Execution in VSCode

When opening suspicious or potentially malicious scripts:

* ❌ **Do NOT enable workspace auto-trust**:

  * Go to `Settings` → Search `security.workspace.trust`
  * Disable: `Security > Workspace > Trust: Enabled`

* ✅ **Open in Restricted Mode**:

  * When prompted, always choose `Restricted Mode`
  * Or open VSCode with `--disable-workspace-trust`

    ```bash
    code --disable-workspace-trust /path/to/suspicious/code
    ```

* ✅ **Turn off all extensions in that folder**:

  * Click on bottom-left yellow bar (Restricted Mode)
  * Disable all extensions for this workspace

* 🛑 **Use Read-Only Mounts** (Optional but safer):

  * Mount a readonly directory:

    ```bash
    sudo mount -o loop,ro /path/to/pcap_mount.iso /mnt/readonly
    ```
  * OR chmod directory to `444` (read-only for everyone):

    ```bash
    chmod -R 444 /your/folder
    ```

* ❌ **Don't use Auto-Run extensions**: Linting / Python interpreters may try to execute code

---

### 2. 🧰 Recommended Tools for KDE/Arch Linux

| Tool            | Purpose                                | Package (Arch)           |
| --------------- | -------------------------------------- | ------------------------ |
| `wireshark-qt`  | GUI Packet Analysis                    | `wireshark-qt`           |
| `tshark`        | CLI Packet Analysis                    | `wireshark-cli`          |
| `capinfos`      | PCAP file metadata                     | (bundled with Wireshark) |
| `vscode`        | Code viewer with restriction config    | `code` (AUR or Flatpak)  |
| `jq`            | Parse JSON output from tools           | `jq`                     |
| `curl` / `wget` | Fetch threat intel via API             | `curl`, `wget`           |
| `whois`         | Check domains / IP ownership           | `whois`                  |
| `python-pip`    | For Python tooling (like malwoverview) | `python-pip`             |
| `clamav`        | Optional CLI virus scan                | `clamav`                 |
| `tor-browser`   | For anonymous threat intel searches    | `tor-browser` (AUR)      |

---

### 3. 🐧 Optional (Offline/Isolated)

If you want to create a safe and minimal analysis environment:

* Create a dedicated user account `maluser` (with no sudo)
* Use `bwrap` or `firejail` to sandbox malicious files
* Store samples in `chmod 444` or `mount -o ro` volumes
* Avoid copying real samples into `$HOME` or workspace folders

---

### 4. 💡 Workflow Suggestion

1. Open PCAP or unknown file inside a read-only folder
2. Use `code --disable-workspace-trust` to view the code
3. Analyze with `tshark`, `capinfos`, `jq`, etc
4. Lookup any suspicious domain/IP with `whois`, `curl`, or threat intel APIs
5. Extract and hash samples offline

---

### 5. 🚨 Pro Tips

* Use a second Linux machine or live USB for testing files
* NEVER allow internet access to a system used to open malware
* Consider using `firejail` or `qemu` to isolate executable samples
* Use `sha256sum` before and after extracting anything

---

```
  ∧___∧
（´・ω・）
_っ＿/￣￣￣/
　＼/＿＿＿/  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```