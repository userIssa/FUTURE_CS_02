# FUTURE_CS_02
# SOC Internship Project – Log Monitoring & Incident Response

This repository documents my internship project simulating the role of a SOC (Security Operations Center) analyst.  
The project demonstrates how to monitor, analyze, and respond to simulated security events using **Splunk SIEM** as the main platform, alongside a custom-built **Python automation script**.

---

## 📊 Splunk Implementation (Main Deliverable)

### 1. Dashboard
A SOC monitoring dashboard was built in Splunk Enterprise 10.0.0 to visualize:
- Malware detections over time
- Top users with malware alerts
- Failed login attempts by user/IP
- Threat type distribution
- Timeline of overall actions

📌 *See `/splunk_screenshots/` for dashboard images.*

### 2. Alerts
The following Splunk alerts were configured:
- **High:** Ransomware/Trojan/Rootkit detection  
- **Medium:** Multiple failed logins from a user  
- **Medium:** Multi-IP logins for a single user  
- **High:** File access within 1 hour after malware detection  

📌 *See `/splunk_screenshots/alerts/` for alert examples.*

### 3. Deliverables
- 📑 [Incident Response Report (PDF)](/reports/Incident_Response_Report-SOC_Internship_Project.pdf)  
- 📂 [Alert Classification Log (Excel/CSV)](/reports/Alert_Classification_Log.xlsx)   
- 📸 [Screenshots from Splunk](/splunk_screenshots/)  

---

## 🐍 Bonus: Python Log Analyzer (Automation)

As a bonus, I built a Python script (`analyze_logs.py`) to replicate SOC analysis outside of Splunk.  

### Features
- Parses SOC-style logs (`SOC_Task2_Sample_Logs.txt`)  
- Detects:
  - Malware events (Ransomware, Trojans, Rootkits, etc.)  
  - Brute-force login attempts  
  - Multi-IP logins  
  - Suspicious file access after malware detection  
- Classifies incidents by severity (High/Medium/Low)  
- Exports:
  - `timeline.csv` (all parsed events)  
  - `incidents.json` (structured incident list)  
  - `report.md` (incident response report)  
  - `email.txt` (incident communication template)  
- Generates charts:
  - Malware detections over time  
  - Threat type distribution  
  - Failed logins by user  
  - Overall action distribution  

### Usage
```bash
python3 analyze_logs.py SOC_Task2_Sample_Logs.txt
```
Outputs are saved in the working directory, with charts stored in /charts/.

## Example Report Snippet
```markdown
### Incident 1
{
  "type": "malware",
  "user": "alice",
  "ip": "198.51.100.42",
  "timestamp": "2025-07-03T04:19:14",
  "threat": "Unknown Malware",
  "severity": "Medium"
}
```

---

📌 Full sample report: /reports/report.md

## 📂 Repository Structure
```bash
/reports
  ├── incident_report.pdf
  ├── Alert_Classification_Log.xlsx
  ├── email.txt
  ├── report.md              # Python auto-generated report
  ├── timeline.csv           # Python timeline export
  ├── incidents.json
/charts                      # Generated visualizations
/splunk_screenshots          # Dashboard + alert screenshots
/script
  └── analyze_logs.py        # Python log analyzer
```

---

## 🎯 Skills Demonstrated
SOC monitoring and alert triage

SIEM (Splunk Enterprise 10.0.0) configuration

Incident detection and classification

Report writing and stakeholder communication

Automation with Python (log parsing, detection, visualization)

---

## 📌 Notes
This project is based on simulated data and was completed as part of my internship training.
It demonstrates real-world SOC workflows and the ability to extend SIEM capabilities with custom automation.
