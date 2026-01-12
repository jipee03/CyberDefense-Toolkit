<div align="center">

| Detection and Analysis Page | Next Phase |
|:-------------------------------------------:|:---------------------------------------------:|
| [Previous Page](./2.0-Detection-and-Analysis.md) | [Containment, Eradication & Recovery](../3-Containment-Eradication-Recovery/3.0-Containment-Eradication-Recovery.md) |

</div>

<br>
<br>
<br>

# SIEM and Logging
Security Information and Event Management (SIEM) and log analysis tools for correlation and detection.

<br>

### Tools Reference Table

<br>

<p align=center>

| Tool | Purpose | Link |
|:-----|:--------|:---------------|
| [**Wazuh**](#wazuh) | SIEM, log analysis, threat detection | [wazuh.com](https://wazuh.com/) |
| [**Splunk**](#splunk) | Log aggregation, SIEM | [splunk.com](https://www.splunk.com/) |
| [**ELK Stack**](#elk-stack) | Log management, analytics | [elastic.co](https://www.elastic.co/what-is/elk-stack) |
| [**Graylog**](#graylog) | Open-source SIEM | [graylog.org](https://www.graylog.org/) |
| [**Atomic Red Team**](#atomic-red-team) | Detection validation/adversary simulation | [atomicredteam.io](https://atomicredteam.io/) |

<br>
<br>

## Atomic Red Team
Framework for testing detection coverage using adversary emulation techniques. Use to validate SIEM rules and monitoring effectiveness.

**Install:**
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git
```
**Usage:**
- Run atomic tests to validate SIEM and EDR detections
- Simulate attacker techniques mapped to MITRE ATT&CK


<br>

#### Practical Examples

> Ingesting Sysmon logs with Wazuh -> see [documentation](https://documentation.wazuh.com/current/user-manual/capabilities/sysmon-monitoring.html)
```bash
# Configure Wazuh agent to forward Sysmon logs from Windows endpoints
```

<br>

> Creating a correlation rule in ELK
```json
{
	"query": {
		"match": {
			"event.action": "user_login"
		}
	}
}
```

<br>

> Running an Atomic Red Team test
```bash
# Example: Simulate credential dumping
Invoke-AtomicTest T1003
```

<br>

#### External References
- [MITRE ATT&CK](https://attack.mitre.org/)
- [DFIR Report](https://thedfirreport.com/)
- [FIRST.org](https://www.first.org/)

<br>
<br>


## Wazuh

Open-source SIEM and security monitoring platform for log analysis, file integrity monitoring, and threat detection.

**Install:**
```bash
curl -sO https://packages.wazuh.com/4.4/wazuh-install.sh && sudo bash ./wazuh-install.sh
```
**Usage:**
- Centralize and analyze logs from endpoints and servers
- Create custom detection rules

<br>

#### Practical Examples

> Ingesting Sysmon logs with Wazuh -> see [documentation](https://documentation.wazuh.com/current/user-manual/capabilities/sysmon-monitoring.html)
```bash
# Configure Wazuh agent to forward Sysmon logs from Windows endpoints
```

<br>

> Creating a custom rule for SSH brute force detection
```xml
<group name="ssh, brute_force,">
	<rule id="5710" level="10">
		<decoded_as>json</decoded_as>
		<field name="event.module">sshd</field>
		<field name="event.action">failed_login</field>
		<description>SSH brute force detected</description>
	</rule>
</group>
```

<br>

#### External References
- [Wazuh Docs](https://documentation.wazuh.com/)

<br>
<br>

## Splunk

Enterprise SIEM and log management platform for large-scale data analysis.

**Install:**
```bash
# Download and install Splunk (see docs for OS-specific steps)
```
**Usage:**
- Ingest logs from multiple sources
- Build dashboards and alerts

<br>

#### Practical Examples

> Creating a dashboard for failed logins
```spl
index=security sourcetype=linux_secure "Failed password" | stats count by src_ip
```

<br>

> Alert for multiple failed logins from same IP
```spl
index=security sourcetype=linux_secure "Failed password" | stats count by src_ip | where count > 10
```

<br>

#### External References
- [Splunk Docs](https://docs.splunk.com/Documentation/Splunk)

<br>
<br>

## ELK Stack

Elasticsearch, Logstash, and Kibana for log aggregation, search, and visualization.

**Install:**
```bash
# See https://www.elastic.co/guide/en/elastic-stack-get-started/current/get-started-elastic-stack.html
```
**Usage:**
- Collect and search logs
- Visualize security events

<br>

#### Practical Examples

> Creating a correlation rule in ELK
```json
{
		"query": {
				"match": {
						"event.action": "user_login"
				}
		}
}
```

<br>

> Visualizing failed logins in Kibana
```json
{
	"aggs": {
		"failed_logins": {
			"terms": { "field": "event.outcome.keyword" }
		}
	}
}
```

<br>

#### External References
- [ELK Stack Docs](https://www.elastic.co/guide/en/elastic-stack-get-started/current/get-started-elastic-stack.html)

<br>
<br>

## Graylog

Open-source log management and SIEM platform.

**Install:**
```bash
# See https://docs.graylog.org/en/latest/pages/installation.html
```
**Usage:**
- Centralize log data
- Create correlation rules

<br>

#### Practical Examples

> Creating a stream for SSH logs
```text
source:ssh AND action:failed
```

<br>

> Alerting on multiple failed logins
```text
source:ssh AND action:failed | count() > 5
```

<br>

#### External References
- [Graylog Docs](https://docs.graylog.org/en/latest/)

