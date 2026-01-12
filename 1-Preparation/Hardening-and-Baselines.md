
# Hardening and Baselines

<br>

### Tools Reference Table

<p align=center>

| Tool | Purpose | Link |
|:-----|:--------|:---------------|
| [**CIS Benchmarks**](#cis-benchmarks) | Security configuration guides | [cisecurity.org](https://www.cisecurity.org/cis-benchmarks/) |
| [**Group Policy**](#group-policy) | Windows policy management | [docs.microsoft.com](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-group-policy-best-practices) |
| [**Ansible/Chef**](#ansiblechef) | Automated configuration management | [ansible.com](https://www.ansible.com/), [chef.io](https://www.chef.io/) |

</p>

<br>
<br>

## CIS Benchmarks
Industry-standard security configuration guides for hardening systems.

**Install:**
```bash
# Download benchmarks from https://www.cisecurity.org/cis-benchmarks/
```
**Usage:**
- Apply recommended settings to OS, applications, and network devices
- Use CIS-CAT Pro for automated assessment

<br>

#### Practical Examples
> Assess system compliance with CIS-CAT
```bash
java -jar CIS-CAT-Assessor.jar -a
```
<br>
<br>

## Group Policy
Windows feature for centralized policy management and enforcement.

**Install:**
```powershell
# Built into Windows Server and Active Directory
```
**Usage:**
- Enforce password policies, audit settings, and security controls
- Apply policies to users and computers via GPOs

<br>

#### Practical Examples
> Set password policy via Group Policy Management Console
```text
Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy
```

<br>
<br>

## Ansible
Automation tools for configuration management and baseline enforcement.

**Install:**
```bash
sudo apt install ansible
sudo apt install chef
```
**Usage:**
- Automate deployment of security baselines
- Remediate configuration drift

<br>

#### Practical Examples
> Apply a security baseline with Ansible
```yaml
- name: Apply CIS baseline
	hosts: all
	roles:
		- cis_benchmark
```

> * This tool is properly designed to build playbooks!
> * Check the Tool chef also

<br>

---

<br>
<br>

<div align="center">

| Previous Page | Next Phase |
|:-------------------------------------------:|:---------------------------------------------:|
| [Preparation Page](./1.0-Preparation.md) | [Detection and Analysis](../2-Detection-and-Analysis/2.0-Detection-and-Analysis.md) |

</div>
