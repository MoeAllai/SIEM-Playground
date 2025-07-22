# Suspicious PowerShell Execution – Detection Rule

🧠 Objective: Detect use of PowerShell for potential post-exploitation or malicious activity on endpoints.

---

## 📌 Use Case

Attackers often use PowerShell to:
- Download payloads
- Bypass defenses
- Run encoded commands
- Establish persistence

---

## 🧪 SPL Query (Splunk)

index=windows sourcetype=WinEventLog:Security EventCode=4104
| search Message="*Invoke*" OR Message="*Base64*" OR Message="*FromBase64String*"
| stats count by user, host, Message
| where count > 1

---

## 🔍 Explanation

- EventCode 4104 → PowerShell Script Block Logging
- Searches for encoded commands or use of dangerous functions like Invoke
- `count > 1` filters noise

---

## 💡 Detection Tips

- Alert when encoded PowerShell appears
- Monitor command line length (very long = suspicious)
- Correlate with 4688 (process creation) for `powershell.exe` with suspicious args

---

🧱 Pyramid of Pain Level: TTP  
🎯 ATT&CK Technique: https://attack.mitre.org/techniques/T1059/001
