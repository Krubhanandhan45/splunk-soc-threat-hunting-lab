Splunk SOC Threat Hunting & Detection Engineering Lab
Complete SIEM Project • Threat Intelligence • Detection Rules • Dashboards • Alerts • Risk Scoring • GeoIP Enrichment
📌 Overview

This project is a fully built Splunk SIEM Home Lab, designed to simulate a real-world SOC Analyst (Blue Team) environment.

It includes:

Log ingestion & parsing

Detection engineering (SPL rules)

Threat intelligence correlation

Brute-force detection

Persistence (cron) detection

Port-scan detection

GeoIP enrichment (attacker map)

Alerts & automation

Dashboard visualizations

Risk scoring & notable events

This project demonstrates the skills required for:

✔ SOC Analyst L1/L2
✔ Threat Hunter
✔ Blue Team / DFIR
✔ SIEM Engineer
✔ Security Monitoring

🏛 Architecture Diagram
            +-------------------------------+
            |         Linux/WLS Host        |
            |  /var/log/auth.log           |
            +---------------+---------------+
                            |
                            v
                +---------------------+
                |     Splunk UF       |
                |   (Universal Fwd)   |
                +---------------------+
                            |
                            v
                +---------------------+
                |     Splunk Core     |
                |  Indexing + Search  |
                +---------------------+
                            |
        ------------------------------------------------
        |                  |                |          |
        v                  v                v          v
  Threat Intel Lookup   Dashboards    Alerts Engine   Risk Scoring
        |                  |                |          |
        ------------------------------------------------
                            |
                            v
                   +----------------+
                   | SOC Monitoring |
                   +----------------+

📁 Repository Structure
splunk-soc-threat-hunting-lab/
│
├── architecture/
│   └── architecture_diagram.png
│
├── lookups/
│   └── threat_intel_blacklist.csv
│
├── spl/
│   ├── brute_force_detection.spl
│   ├── threat_intel_lookup.spl
│   ├── correlation_rule.spl
│   ├── cron_persistence.spl
│   ├── port_scan_detection.spl
│   ├── risk_scoring.spl
│   ├── notable_events.spl
│   └── dashboard_queries.spl
│
├── dashboards/
│   ├── soc_dashboard.xml
│   ├── threat_intel_panel.xml
│   ├── geoip_map.xml
│   ├── risk_score_panel.xml
│
├── alerts/
│   ├── brute_force_alert.txt
│   ├── threat_intel_alert.txt
│   └── notable_event_alert.txt
│
├── screenshots/
│   ├── dashboard.png
│   ├── brute_force.png
│   ├── threat_intel.png
│   ├── geoip_map.png
│   ├── risk_scoring.png
│   └── notable_event.png
│
├── docs/
│   └── Splunk_SIEM_SOC_CourseBook.pdf
│
└── README.md

🎯 Features Implemented
🔐 1. SSH Brute-Force Detection

Detect repeated failed logins

Extract attacker IP

Count failures and threshold alerting

SPL:
(In /spl/brute_force_detection.spl)

🔎 2. Threat Intelligence Lookup Correlation

Detect if an IP exists in a custom TI blacklist

Add risk metadata (description + threat level)

Identify malicious sources in logs

CSV: /lookups/threat_intel_blacklist.csv
SPL: /spl/threat_intel_lookup.spl

🧪 3. Correlation Rule – Success After Multiple Failures

Detect possible credential compromise:

Multiple failed logins

Followed by a successful login

From the same IP

SPL: /spl/correlation_rule.spl

🕒 4. Persistence – Cron Malware Detection

Detect unauthorized cron job creation via:

/var/log/syslog

/etc/crontab

/etc/cron.d/

SPL: /spl/cron_persistence.spl

🌐 5. Port Scan Detection

Detect horizontal & vertical scanning via unique ports.

SPL: /spl/port_scan_detection.spl

🌍 6. GeoIP Enrichment + Threat Map

Enrich attacker IP with Country/City

Create a world map of threat sources

SPL: /spl/dashboard_queries.spl
Dashboard: /dashboards/geoip_map.xml

🔔 7. Alerts Engine

Alerts created:

SSH brute-force alert

Threat intelligence match alert

Notable event (risk scored)

Stored under /alerts/

🚨 8. Risk Scoring Engine (Mini Splunk ES)

Threat levels → numeric scores:

level	score
high	90
medium	60
low	30

Produces:

total_risk

severity (critical/high/medium)

SPL: /spl/risk_scoring.spl

🚨 9. Notable Events

A detection becomes a notable event if:

risk_score ≥ 80 → critical

risk_score ≥ 60 → high

SPL: /spl/notable_events.spl

📊 Dashboards Included
1️⃣ SOC Monitoring Dashboard

Brute-force attack panel

Threat intel match panel

GeoIP attack map

Risk score chart

Notable events

2️⃣ Threat Intel Panel

XML included in /dashboards/.

🧨 Attack Simulation

Use these commands to generate logs:

➤ SSH brute-force simulation:
for i in {1..10}; do ssh invalid@127.0.0.1; done

➤ Fake external attacker (trigger TI lookup):
logger "Failed password for root from 45.155.205.123 port 22 ssh2"

➤ Port scanning:
nmap -Pn -p 1-2000 127.0.0.1

➤ Cron persistence:
echo "* * * * * root echo HACKED >> /tmp/pwned" | sudo tee /etc/cron.d/hacked

👨‍💻 Skills Demonstrated

✔ SPL (Search Processing Language)
✔ Threat hunting
✔ Log parsing
✔ Detection engineering
✔ Lookups
✔ Security dashboards
✔ Alerts & correlation
✔ GeoIP
✔ Risk scoring
✔ Notable events
✔ SIEM architecture
✔ Linux log analysis

💼 Interview Talking Points

If they ask “Explain your SOC project”, answer:

I built a complete Splunk SIEM home lab including ingestion, enrichment, detection, dashboards, alerts, and threat intelligence correlation.
I created custom SPL-based detection rules for brute-force attacks, cron persistence, and port scans, and enriched logs with GeoIP and threat intel lookup tables.
I also implemented a risk-scoring engine similar to Splunk Enterprise Security and created notable events with automated alerting.

📝 Future Enhancements (Optional)

Slack webhook alerts

Automated blocking via script

MITRE ATT&CK mapping

UEBA anomaly scores

Sysmon ingestion

Windows event log hunting

📧 Contact

Your Name
SOC Analyst / Threat Hunter
GitHub: your link
LinkedIn: your link
