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
