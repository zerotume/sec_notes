## 🔄 SMB Lateral Movement Attack (admin$ example) — Full Flow

### 🎯 Objective

Use SMB to move laterally across machines by writing a payload to the `admin$` share and executing it remotely.

---

### 🧱 Step-by-Step Breakdown

#### 1. 📡 Connection Establishment

- Attacker connects to TCP port **445** on the victim machine.
- Starts an **SMB session**.
- Sends **NTLMSSP** authentication (can be extracted from `ntlmssp.*` fields).

#### 2. 🌳 Tree Connect to `admin$`

- `admin$` is a **default administrative share** pointing to `C:\Windows\`.
- Tree Connect request like:
```
Tree Connect Request → \<victim-ip>\admin$
```

- This gives attacker access to write files to the system directory.

#### 3. 💾 File Creation

- Attacker sends:
```
Create Request → \Temp\malicious.exe
Write Request → actual payload bytes
Close Request → done writing
```

- These can be tracked via `smb2.create.*` and `smb2.write.*`.

#### 4. 🚀 Remote Execution

- Common tools: `PsExec`, `WMI`, `WinRM`, `SC`, `schtasks`.
- `PsExec` creates a remote service pointing to the payload.
- Triggered via SMB named pipe: `\\<victim>\svcctl` or `\\pipe\atsvc`.

---

### 🧠 What to Look for (Defender Tips)

- **Unusual Tree Connects**:
- To `admin$`, `C$`, `IPC$` shares.
- **NTLMSSP authentication**:
- Sudden use of NTLM in lateral movement window.
- **File write to system dirs**:
- Especially in `admin$` path like `Windows\Temp\`.
- **Service creation over SMB**:
- Named pipe `svcctl` traffic.
- **No corresponding user activity**:
- No mouse/keyboard interaction or normal user behavior.

---

### 🔬 Packet Fields to Watch

- `smb2.cmd == 3` (Tree Connect)
- `smb2.tree` (target share)
- `ntlmssp.target_name`
- `smb2.filename`
- `smb2.create.action`

---

### 🧪 Real-World Tool Chain

- `Impacket`’s `psexec.py`:
- Connects, writes to `admin$`, creates a service.
- `CrackMapExec` or `SMBexec`:
- Use similar approaches via NTLM auth.

---

### 🔧 Detection Tools

- **Wireshark**:
- Use display filter:
  ```
  smb2 && tcp.port == 445
  ```
- **Zeek**:
- Watch for:
  - `SMB::TreeConnect`
  - `SMB::WriteRequest`
  - `NTLM::Logon`

- **ELK / SIEM**:
- Search:
  ```
  share_name:"admin$" AND event_type:"file_write"
  ```

---

> _"If someone’s dropping binaries into `admin$`, assume they’re not installing Solitaire."_ 🎮
