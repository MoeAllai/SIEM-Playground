# PsExec Lateral Movement – Detection Rule

🧠 Objective: Detect use of PsExec or similar tools for lateral movement between systems in a Windows environment.

---

## 📌 Use Case

Adversaries use PsExec to:
- Execute commands remotely
- Transfer malware or tools
- Move laterally across systems

---

## 🧪 SPL Query (Splunk)

index=windows sourcetype=WinEventLog:Security EventCode=4688
| search New_Process_Name="*psexec*" OR CommandLine="*\\*\\admin$*"
| stats count by user, host, New_Process_Name, CommandLine

---

## 🔍 Explanation

- EventCode 4688 → process creation
- Filters for process name or command line showing PsExec usage
- `\\target\admin$` is a known PsExec behavior

---

## 💡 Detection Tips

- Alert on PsExec use in production
- Combine with EventCode 4624 (remote logins)
- Watch for svc_ accounts or unknown users running PsExec

---

🧱 Pyramid of Pain Level: TTP  
🎯 ATT&CK Technique: https://attack.mitre.org/techniques/T1021/002
