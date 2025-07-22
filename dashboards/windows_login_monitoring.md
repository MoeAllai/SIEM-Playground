# Windows Login Monitoring – Splunk Dashboard Concept

🧠 Objective: Visualize successful and failed logins across all Windows hosts in a network to detect anomalies and brute-force attempts.

---

## Panels Included

1. Total Logins by Hour  
index=windows sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625)  
| timechart span=1h count by EventCode

2. Top Failed Login Sources  
index=windows EventCode=4625  
| stats count by src, user  
| sort -count

3. Most Active Users  
index=windows EventCode=4624  
| stats count by user  
| sort -count

4. Logins by Country (if using GeoIP)  
index=windows EventCode=4624  
| iplocation src  
| stats count by Country

---

## Dashboard Notes

- Designed to detect brute-force login attempts, lateral movement, or compromised accounts  
- Can be used to generate alerts when thresholds are met  
- Easy to modify for specific servers or admin accounts

---

Room Inspired By: TryHackMe Labs + Splunk Free
