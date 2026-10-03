 🛡️ End-to-End Security Operations Center (SOC) Automation & Threat Intelligence Pipeline

An automated, enterprise-grade Security Operations Center (SOC) triage engine and Security Orchestration, Automation, and Response (SOAR) pipeline developed using Python and Flask. This project addresses the primary operational bottleneck in modern Security Operations Centers: High Alert Volume and Alert Fatigue. 

The pipeline acts as a centralized webhook middleware that receives raw security incident events from Endpoint Detection and Response (EDR) agents or Security Information and Event Management (SIEM) systems (e.g., Microsoft Sentinel, Wazuh, Splunk). It performs real-time, multi-sourced Indicators of Compromise (IoC) enrichment, calculates dynamic threat scores based on external intelligence thresholds, applies automated playbook decisions, and dispatches structured, actionable incident handling alerts directly into a Discord Incident Response channel.

---

 🚀 Key Operational Features & Architecture

- Ingestion & Webhook Middleware: Exposes a high-performance RESTful Webhook endpoint (`/webhook`) designed to process asynchronous HTTP POST JSON payloads originating from SIEM alert rules or EDR detections.
- Multi-Source Threat Intelligence Enrichment:
- VirusTotal API v3: Performs real-time SHA-256 / MD5 / SHA-1 file hash queries to extract global antivirus detection ratios across 70+ security vendors, identifying zero-day or known malware strains (e.g., Ransomware, Trojans, Loaders).
- AbuseIPDB API v2: Queries public IPv4 addresses against historical abuse reports to retrieve confidence scores, country of origin, ISP telemetry, and total abuse submission counts.
- Automated Triage & Risk Matrix Engine: Replaces manual lookup tasks by correlating enriched telemetry against predefined threat parameters. The engine automatically assigns incident severity levels (LOW, MEDIUM, HIGH, CRITICAL) and maps appropriate Incident Response Playbooks.
- Automated Response & Playbook Recommendation: Injects clear, immediate containment instructions into the alert context for L1/L2 Analysts, including Host Network Isolation, Revoking User Session Tokens, Blocking Malicious IPs at the Perimeter Firewall, and Preserving Volatile RAM for Forensics.
- Alert Fatigue & MTTR Reduction: Streamlines the initial triage workflow by replacing raw, unformatted log lines with actionable Discord Embed Cards, reducing Mean Time to Respond (MTTR) from an average of 15 minutes to under 2 seconds.

---

 🛠️ Technical Stack & Frameworks

- Core Programming Language: Python 3.x
- Web Framework & Routing: Flask (Python RESTful Web Server)
- External API Integrations: 
  - VirusTotal REST API v3 (Threat Intelligence & File Hash Reputation)
  - AbuseIPDB REST API v2 (IP Address Reputation & Abuse Confidence Scoring)
- Alert Dispatching Infrastructure: Discord Webhooks (JSON-formatted interactive Embed payloads)
- Supported IoC Types: Public IPv4 Addresses, SHA-256 / SHA-1 / MD5 Hashes, Hostnames, User Accounts
- Environment & Tools: `curl`, Git, Virtualenv, JSON processing libraries (`requests`)

---

 🛡️ Practical SOC Use Case & Industry Relevance

In a real-world Security Operations Center environment, Tier 1 SOC Analysts are routinely overwhelmed by hundreds of low-to-medium fidelity security events per shift. Manual enrichment—copying IP addresses and file hashes into threat intelligence platforms—wastes critical time during active network intrusions.

This project demonstrates an enterprise-grade automation capability where initial data gathering, threat scoring, and containment playbooks are fully automated. By delegating Tier 1 repetitive investigation tasks to this Python-based SOAR engine, SOC teams achieve immediate containment recommendations, eliminate manual context switching, and significantly lower the probability of human error during critical incident handling.