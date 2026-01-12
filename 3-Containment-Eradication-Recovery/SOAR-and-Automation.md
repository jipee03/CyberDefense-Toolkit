

# SOAR and Automation

<br>

### Tools Reference Table

<p align=center>

| Tool | Purpose | Link |
|:-----|:--------|:---------------|
| [**Cortex XSOAR**](#cortex-xsoar) | Playbook-driven automation | [paloaltonetworks.com](https://www.paloaltonetworks.com/cortex/xsoar) |
| [**Splunk SOAR**](#splunk-soar) | Automated response actions | [splunk.com](https://www.splunk.com/en_us/software/soar.html) |
| [**Custom Scripts**](#custom-scripts) | Scripting for automation | [awesome-incident-response](https://github.com/meirwah/awesome-incident-response) |

</p>

<br>
<br>

## Cortex XSOAR
Playbook-driven automation platform for orchestrating incident response.

**Install:**
```bash
# See Palo Alto Networks documentation for installation
```
**Usage:**
- Build automated playbooks for incident response
- Integrate with SIEM, EDR, and ticketing systems

<br>

#### Practical Examples
> Run a playbook to auto-contain phishing incidents
```text
# Use XSOAR UI to trigger playbook on phishing alert
```
<br>
<br>

## Splunk SOAR
Automated response platform for security operations.

**Install:**
```bash
# See Splunk SOAR documentation for installation
```
**Usage:**
- Automate repetitive security tasks
- Integrate with Splunk SIEM and other tools

<br>

#### Practical Examples
> Auto-block malicious IPs from SIEM alerts
```python
# Example Python block action in SOAR playbook
block_ip(ip="1.2.3.4")
```
<br>
<br>

## Custom Scripts
Python, PowerShell, and Bash scripts for automating incident response tasks.

**Install:**
```bash
# Ensure Python, PowerShell, or Bash is installed
```
**Usage:**
- Automate log collection, alerting, and remediation

<br>

#### Practical Examples
> Python script to collect logs from endpoints
```python
import os
os.system('scp /var/log/syslog user@server:/logs/')
```

<br>

---

<br>
<br>

<div align="center">

| Previous Page | Next Phase |
|:-------------------------------------------:|:---------------------------------------------:|
| [CER Page](./3.0-Containment-Eradication-Recovery.md) | [Post-Incident Activity](../4-Post-Incident-Activity/4.0-Post-Incident-Activity.md) |

</div>
