<div align="center">

| Detection and Analysis Page | Next Phase |
|:-------------------------------------------:|:---------------------------------------------:|
| [Previous Page](./2.0-Detection-and-Analysis.md) | [Containment, Eradication & Recovery](../3-Containment-Eradication-Recovery/3.0-Containment-Eradication-Recovery.md) |

</div>

<br>
<br>
<br>

# Digital Forensics

<br>

### Tools Reference Table

<p align=center>

| Tool | Purpose | Link |
|:-----|:--------|:---------------|
| [**Volatility**](#volatility) | Memory forensics | [volatility3.org](https://volatility3.org/) |
| [**Autopsy**](#autopsy) | Disk forensics | [sleuthkit.org/autopsy](https://www.sleuthkit.org/autopsy/) |
| [**Wireshark**](#wireshark) | Packet capture & analysis | [wireshark.org](https://www.wireshark.org/) |

</p>

<br>
<br>

## Volatility
Memory forensics framework for analyzing RAM dumps.

**Install:**
```bash
pip install volatility3
```
**Usage:**
- Analyze memory images for processes, network connections, and malware

<br>

#### Practical Examples
> List running processes in a memory image
```bash
vol.py -f memdump.raw windows.pslist
```

<br>
<br>

## Autopsy
Open-source digital forensics platform for disk analysis.

**Install:**
```bash
# Download from https://www.sleuthkit.org/autopsy/
```
**Usage:**
- Analyze disk images for files, artifacts, and timelines

<br>

#### Practical Examples
> Ingest a disk image and view file system timeline
```text
# Use Autopsy GUI to add data source and run timeline analysis
```


<br>
<br>

## Wireshark
Network protocol analyzer for packet capture and deep inspection.

**Install:**
```bash
sudo apt install wireshark
```
**Usage:**
- Capture and analyze network traffic
- Investigate security incidents

<br>

#### Practical Examples
> Filter HTTP traffic in a PCAP
```text
http.request
```
<br>
#### External References
- [Wireshark Docs](https://www.wireshark.org/docs/)
