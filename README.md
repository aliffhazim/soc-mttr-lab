# soc-mttr-lab

> **Cut simulated incident response time from 8 seconds to 2 seconds, using a detection rule I designed, tuned, and defended myself.**

## Executive Summary
- **The problem:** Undetected credential-based intrusions are expensive. [IBM's 2025 breach research](https://www.ibm.com/reports/data-breach) puts a $1.88M cost gap between fast and slow containment. It's also a theme large hardware vendors are addressing directly, [through hardware-based credential protection and passwordless strategies](https://www.dell.com/en-us/blog/how-to-weather-the-cyber-identity-crisis/).
- **What I built:** A live, two-machine attack simulation with a custom Wazuh detection rule mapped to [MITRE ATT&CK T1110.004](https://attack.mitre.org/techniques/T1110/004/), engineered to automatically measure response time.
- **The impact:** Detect-to-contain time cut from 8s to 2s, backed by real logs, not estimates. [A Schlumberger security lead described the same triage-speed problem](https://jpt.spe.org/oil-and-gas-data-multiply-so-do-cybersecurity-threats) at enterprise scale, this project is a small, hands-on version of that exact challenge.

## Architecture

![Architecture](docs/screenshots/00-architecture-diagram.png)

## Results

| Run | MTTR |
|---|---|
| hydra01 | 8s |
| hydra02 | 2s |

*Two runs, not a statistical trend, a real demonstration that response time is trainable.*

## Response Lifecycle ([NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf))

| Function | What I Did |
|---|---|
| **Identify** | Researched current credential-stuffing prevalence to build a realistic, evidence-based scenario |
| **Protect** | Tuned the detection threshold to 5 attempts/60s, aligned with fail2ban's real-world convention |
| **Detect** | Custom Wazuh rule flags the pattern live, mapped to MITRE T1110.004 |
| **Respond** | Automated timestamp logging measured the full detect-to-contain window |
| **Recover** | Found and fixed a stale-alert-matching bug inflating results; recommended key-based SSH, auto-lockout, and MFA for production hardening |

**Relevant to:** SOC Analyst · Incident Response · SIEM (Wazuh) · MITRE ATT&CK · Python · Detection Engineering · MTTR
