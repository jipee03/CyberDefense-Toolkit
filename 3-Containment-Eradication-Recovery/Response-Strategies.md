
# Response Strategies

<br>

### Tools Reference Table

<p align=center>

| Tool | Purpose | Link |
|:-----|:--------|:---------------|
| [**SOAR Platforms**](#soar-platforms) | Incident response automation | [paloaltonetworks.com](https://www.paloaltonetworks.com/cortex/xsoar) |
| [**EDR**](#edr) | Endpoint isolation & remediation | [crowdstrike.com](https://www.crowdstrike.com/) |
| [**Backup/Restore**](#backuprestore) | System recovery | [veeam.com](https://www.veeam.com/) |

</p>

<br>
<br>

## SOAR Platforms
Security Orchestration, Automation, and Response platforms for automating incident response workflows (e.g., Cortex XSOAR, Splunk SOAR).

**Install:**
```bash
# See vendor documentation for installation
```
**Usage:**
- Automate containment, eradication, and recovery actions
- Integrate with SIEM, EDR, and ticketing systems

<br>

#### Practical Examples
> Auto-isolate infected endpoints via playbook
```text
# Use SOAR UI to trigger endpoint isolation workflow
```

<br>
<br>

## EDR
Endpoint Detection & Response solutions for isolating and remediating compromised hosts (e.g., CrowdStrike, SentinelOne).

**Install:**
```bash
# See vendor documentation for installation
```
**Usage:**
- Isolate affected systems
- Remediate threats and restore normal operations

<br>

#### Practical Examples
> Quarantine endpoint using EDR console
```text
# Use EDR platform UI to quarantine host
```
<br>
<br>

## Backup/Restore
Tools for system backup and recovery (e.g., Veeam, Acronis).

**Install:**
```bash
# See vendor documentation for installation
```
**Usage:**
- Restore systems from clean backups after containment and eradication
- Test backup integrity regularly

<br>

#### Practical Examples
> Restore server from backup
```text
# Use backup software UI to select and restore backup
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
