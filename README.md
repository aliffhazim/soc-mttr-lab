# SOC Incident Response Lab: Credential-Stuffing Detection

**Cut simulated incident response time from 8 seconds to 2 seconds, using a detection rule I designed, tuned, and defended myself.**

**Jump to:** [Executive Summary](#executive-summary) · [Architecture](#architecture) · [Results](#results) · [Response Lifecycle](#response-lifecycle-nist-csf-20) · [Full Technical Breakdown](#full-technical-breakdown) · [References](#references)

## Executive Summary
- **The problem:** Undetected credential-based intrusions are expensive. [IBM's 2025 breach research](https://www.ibm.com/think/insights/data-matters/cost-of-a-data-breach) puts a $1.88M cost gap between fast and slow containment. It's also a theme large hardware vendors are addressing directly, [through hardware-based credential protection and passwordless strategies](https://www.dell.com/en-us/blog/how-to-weather-the-cyber-identity-crisis/).
- **What I built:** A live, two-machine attack simulation with a custom detection rule mapped to [MITRE ATT&CK T1110.004](https://attack.mitre.org/techniques/T1110/004/), built on Wazuh, a SIEM (Security Information and Event Management platform), engineered to automatically measure response time.
- **The impact:** Detect-to-contain time cut from 8s to 2s, backed by real logs, not estimates. [A Schlumberger security lead described the same triage-speed problem](https://jpt.spe.org/oil-and-gas-data-multiply-so-do-cybersecurity-threats) at enterprise scale, this project is a small, hands-on version of that exact challenge.

## Architecture

*Two machines, one attack, fully automated measurement:*

![Architecture](docs/screenshots/00-architecture-diagram.png)

## Results

*MTTR (Mean Time to Respond), measured automatically, not estimated:*

| Run | MTTR |
|---|---|
| hydra01 | 8s |
| hydra02 | 2s |

*Two runs, not a statistical trend, a real demonstration that response time is trainable.*

## Response Lifecycle ([NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf))

| Function | What I Did |
|---|---|
| **Identify** | Researched current credential-stuffing prevalence to build a realistic, evidence-based scenario |
| **Protect** | Tuned the detection threshold to 5 attempts/60s to avoid flagging genuine password mistakes, based on real-world lockout conventions |
| **Detect** | Custom Wazuh rule flags the pattern live, mapped to MITRE T1110.004 |
| **Respond** | Automated timestamp logging measured the full detect-to-contain window |
| **Recover** | Found and fixed a stale-alert-matching bug inflating results; recommended key-based SSH, auto-lockout, and MFA for production hardening |

**Relevant to:** SOC Analyst · Incident Response · SIEM (Wazuh) · MITRE ATT&CK · Python · Detection Engineering · MTTR

## Full Technical Breakdown

**Tech stack**

| Layer | Tools |
|---|---|
| SIEM | Wazuh 4.14 (indexer, manager, dashboard) |
| Attack simulation | Kali Linux, Hydra |
| Automation | Python 3 |
| Environment | VMware Workstation, Ubuntu 24.04 + Kali, both running real Wazuh agents |

**The detection rule**
```xml
<rule id="100010" level="10" frequency="5" timeframe="60">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>5+ SSH authentication failures from same source within 60s, possible credential stuffing</description>
  <mitre><id>T1110.004</id></mitre>
</rule>
```

**Screenshots**

![Dashboard](docs/screenshots/01-dashboard-overview.png)
*Figure 1: Wazuh dashboard, live agent connected, real alert volume.*

![MITRE mapping](docs/screenshots/02-mitre-dashboard-100010.png)
*Figure 2: Alerts filtered to rule 100010, MITRE ATT&CK panel confirming Credential Stuffing.*

![Alert events](docs/screenshots/03-alert-events-list.png)
*Figure 3: Six real detections with timestamps, the raw evidence behind Figure 2's chart.*

![Attack terminal](docs/screenshots/04-hydra-attack-terminal.png)
*Figure 4: The actual credential-stuffing attack, launched from Kali against the target.*

![Report output](docs/screenshots/05-generate-report-output.png)
*Figure 5: generate_report.py producing the real 8s-to-2s comparison automatically.*

![Detection rule](docs/screenshots/06-detection-rule-code.png)
*Figure 6: The custom Wazuh rule itself, confirmed directly from the file.*

**All bugs hit and resolved**
- Disk too small for Wazuh's full stack, resized and repartitioned
- Wrong usernames in the attack list triggered the wrong rule entirely
- Timezone mismatch crashed the timing script, made both sides UTC-aware
- Stale alert matching silently inflated a result, fixed by matching each triage to the closest prior detection

**Run it**
```bash
git clone https://github.com/aliffhazim/soc-mttr-lab
python3 triage_tool/mark_event.py <run_id> triaged
python3 triage_tool/mark_event.py <run_id> contained
sudo python3 triage_tool/generate_report.py
```

## References
- IBM Cost of a Data Breach Report 2025 — https://www.ibm.com/think/insights/data-matters/cost-of-a-data-breach
- Dell Technologies, "How To Weather the Cyber Identity Crisis" — https://www.dell.com/en-us/blog/how-to-weather-the-cyber-identity-crisis/
- Journal of Petroleum Technology, alert-triage automation in energy/critical infrastructure — https://jpt.spe.org/oil-and-gas-data-multiply-so-do-cybersecurity-threats
- MITRE ATT&CK, T1110.004 Credential Stuffing — https://attack.mitre.org/techniques/T1110/004/
- NIST SP 800-61r3, Incident Response Recommendations (CSF 2.0) — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
