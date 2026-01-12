<div align="center">

| Detection and Analysis Page | Next Phase |
|:-------------------------------------------:|:---------------------------------------------:|
| [Previous Page](./2.0-Detection-and-Analysis.md) | [Containment, Eradication & Recovery](../3-Containment-Eradication-Recovery/3.0-Containment-Eradication-Recovery.md) |

</div>

<br>
<br>
<br>

# Monitoring Sensors

<br>

### Tools Reference Table

<p align=center>

| Tool | Purpose | Link |
|:-----|:--------|:---------------|
| [**EDR**](#edr-endpoint-detection--response) | Endpoint detection & response | [crowdstrike.com](https://www.crowdstrike.com/) |
| [**Sysmon**](#sysmon) | Windows event logging | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| [**Zeek**](#zeek) | Network traffic analysis | [zeek.org](https://zeek.org/) |
| [**Suricata**](#suricata) | Network IDS/IPS | [suricata.io](https://suricata.io/) |
| [**PCAP Tools**](#pcap-tools) | Packet capture & analysis | [wireshark.org](https://www.wireshark.org/) |
| [**Flow Data**](#flow-data) | Network flow monitoring | [nfdump](https://github.com/phaag/nfdump) |
| [**ICS/SCADA Monitoring**](#icsscada-monitoring) | OT/ICS network monitoring | [securityonion.net](https://securityonion.net/) |

</p>


<br>
<br>
<br>

## EDR (Endpoint Detection & Response)
Commercial and open-source EDR solutions for endpoint visibility and response (e.g., CrowdStrike, SentinelOne, OSQuery).

**Install:**
```bash
# See vendor documentation for installation
```
**Usage:**
- Detect and respond to endpoint threats
- Isolate compromised hosts

<br>

#### Practical Examples
> Isolating a compromised endpoint (CrowdStrike example)
```bash
# Use Falcon UI or API to quarantine host
```

<br>
<br>

## Sysmon
Windows system monitoring tool for detailed event logging.

**Install:**
```powershell
# Download from Microsoft Sysinternals
```
**Usage:**
- Log process creation, network connections, and more
- Integrate with SIEM for alerting

<br>

#### Practical Examples
> Monitor process creation events
```xml
<EventFiltering>
	<Rule groupRelation="or">
		<ProcessCreate onmatch="include" />
	</Rule>
</EventFiltering>
```

<br>
<br>

## Zeek
Network analysis framework for traffic inspection and threat hunting.

**Install:**
```bash
sudo apt install zeek
```
**Usage:**
- Monitor network traffic
- Detect suspicious activity

<br>

#### Practical Examples
> Capture HTTP traffic
```bash
zeek -r capture.pcap
```

<br>
<br>

## Suricata
Open-source network IDS/IPS and traffic analysis tool.

**Install:**
```bash
sudo apt install suricata
```
**Usage:**
- Real-time intrusion detection
- Analyze network flows

<br>

#### Practical Examples
> Run Suricata on a network interface
```bash
sudo suricata -i eth0
```

<br>
<br>

## PCAP Tools
Packet capture tools for network forensics (e.g., tcpdump, Wireshark).

**Install:**
```bash
sudo apt install tcpdump wireshark
```
**Usage:**
- Capture and analyze network traffic

<br>

#### Practical Examples
> Capture all traffic on eth0
```bash
sudo tcpdump -i eth0 -w capture.pcap
```

<br>
<br>

## Flow Data
NetFlow, sFlow, and IPFIX for network flow monitoring.

**Install:**
```bash
# See nfdump, pmacct, or vendor docs
```
**Usage:**
- Monitor network flows for anomalies

<br>

#### Practical Examples
> Analyze NetFlow data with nfdump
```bash
nfdump -r netflowfile
```

<br>
<br>

## ICS/SCADA Monitoring
Specialized tools for industrial environments (e.g., Security Onion, GRASSMARLIN).

**Install:**
```bash
# See Security Onion or GRASSMARLIN docs
```
**Usage:**
- Monitor OT networks for threats

<br>

#### Practical Examples
> Scan ICS network with GRASSMARLIN
```bash
grassmarlin -i eth1
```
