# Windows Failed Logins – Detection Rule

🧠 Objective: Detect brute-force attempts or suspicious login failures on Windows endpoints using SPL.

---

## 📌 Use Case

Repeated login failures (EventCode 4625) may indicate:
- Brute-force password attack
- Unauthorized access attempt
- Account lockout attempts

---

## 🧪 SPL Query (Splunk)

index=windows sourcetype=WinEventLog:Security EventCode=4625
| stats count by user, src, host
| where count > 5

---

## 🔍 Explanation

- EventCode=4625 → failed login
- count > 5 → filters out occasional mistypes
- Can customize to filter by time window:
  earliest=-1h@h latest=now

---

## 💡 Detection Tips

- Add alerting when count > threshold
- Correlate with EventCode 4624 (successful login)
- Monitor high-value accounts (e.g., admin, svc_ accounts)

---

🧱 Pyramid of Pain Level: TTP  
🎯 ATT&CK Technique: https://attack.mitre.org/techniques/T1078/
