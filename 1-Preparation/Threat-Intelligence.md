# Threat Intelligence

Threat intelligence is the foundation of proactive defense, enabling security teams to understand adversary capabilities, intentions, and tradecraft. This guide covers essential platforms and frameworks for collecting, analyzing, and operationalizing threat intelligence.

<br>

### Tools Reference Table

| Platform | Primary Use Case | Deployment Model | Official Link |
|:---------|:----------------|:-----------------|:--------------|
| **MISP** | IOC sharing & correlation | Self-hosted / Cloud | [misp-project.org](https://www.misp-project.org/) |
| **OpenCTI** | Knowledge graph & analysis | Self-hosted / Cloud | [opencti.io](https://www.opencti.io/) |
| **MITRE ATT&CK** | TTP framework & mapping | Reference / Tool | [attack.mitre.org](https://attack.mitre.org/) |
| **ATT&CK Navigator** | Technique visualization | Web-based / Local | [mitre-attack.github.io](https://mitre-attack.github.io/attack-navigator/) |

<br>
<br>

## Threat Intelligence Lifecycle
Understanding the intelligence lifecycle helps structure your threat intelligence program:

### 1. **Planning & Direction**
* Define intelligence requirements, collection priorities, and stakeholder needs.

### 2. **Collection**
* Gather raw data from feeds, open sources, industry sharing groups, and internal telemetry.

### 3. **Processing**
* Normalize, deduplicate, and structure collected data into usable formats.

### 4. **Analysis**
* Extract insights, identify patterns, and contextualize threats to your environment.

### 5. **Dissemination**
* Share intelligence with appropriate stakeholders in actionable formats.

### 6. **Feedback**
* Refine requirements based on intelligence effectiveness and stakeholder input.

<br>

## MISP (Malware Information Sharing Platform)
MISP is an open-source threat intelligence platform designed for sharing, storing, and correlating Indicators of Compromise (IOCs) and threat information. It excels at collaborative intelligence sharing across organizations and communities.

### Key Features

- **Flexible Event Model** - Rich data structures for threat events and attributes
- **Automatic Correlation** - Links related indicators across events
- **Feed Management** - Import/export from hundreds of threat feeds
- **API & Integrations** - RESTful API for automation and SIEM integration
- **Taxonomy & Tagging** - Standardized classification with MISP taxonomies
- **Community Sharing** - Connect with trusted communities and sharing groups
- **Privacy Controls** - Granular distribution levels and sharing restrictions

### Installation & Setup

**Using Docker (Recommended):**
```bash
# Clone MISP Docker repository
git clone https://github.com/MISP/misp-docker.git
cd misp-docker

# Configure environment
cp template.env .env
# Edit .env with your settings (BASE_URL, passwords, etc.)

# Start MISP
docker-compose up -d

# Access MISP
# URL: https://localhost
# Default credentials: admin@admin.test / admin
```

**Manual Installation (Ubuntu):**
```bash
# Download and run installation script
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
chmod +x /tmp/INSTALL.sh
sudo /tmp/INSTALL.sh -A

# Follow prompts for configuration
# Installation guide: https://misp.github.io/MISP/INSTALL.ubuntu2204/
```

**Initial Configuration:**
```bash
# Access MISP web interface
# Navigate to Administration > Server Settings & Database

# Configure base URL
# Set: MISP.baseurl = https://your-misp-instance.com

# Enable background workers
# Set: SimpleBackgroundJobs.enabled = true

# Configure email notifications
# Set SMTP settings in Email section
```

### Usage Guidelines

**Intelligence Workflow:**
1. **Collect** - Import feeds and receive shared events
2. **Enrich** - Add context with threat intelligence modules
3. **Correlate** - Identify relationships between indicators
4. **Share** - Distribute to trusted communities
5. **Export** - Push to detection systems (SIEM, IDS, firewalls)

**Key Concepts:**
- **Events** - Containers for related threat information
- **Attributes** - Individual indicators (IPs, domains, hashes, etc.)
- **Objects** - Structured templates (malware samples, attack patterns)
- **Tags** - Classification labels (TLP, PAP, threat actor names)
- **Galaxies** - Advanced threat knowledge (APT groups, tools, techniques)

### Practical Examples

**Create a new threat event:**
```bash
# Using PyMISP (Python library)
from pymisp import PyMISP, MISPEvent

# Initialize connection
misp = PyMISP('https://your-misp-instance.com', 'YOUR_API_KEY', ssl=True)

# Create new event
event = MISPEvent()
event.info = 'Phishing campaign targeting finance sector'
event.distribution = 1  # Community only
event.threat_level_id = 2  # Medium
event.analysis = 1  # Ongoing

# Add attributes
event.add_attribute('domain', 'malicious-domain.com', comment='C2 domain')
event.add_attribute('ip-dst', '192.0.2.100', comment='C2 IP address')
event.add_attribute('md5', 'ac3d5bbfdb143a1c0b0be884e65f3d32', comment='Malware hash')

# Add tags
event.add_tag('tlp:amber')
event.add_tag('misp-galaxy:threat-actor="APT28"')

# Push to MISP
misp.add_event(event, pythonify=True)
```

**Import threat feed:**
```bash
# Configure feed via web interface:
# Sync Actions > List Feeds > Add Feed

# Example: Import AlienVault OTX feed
# Name: AlienVault OTX
# Provider: AlienVault
# URL: https://otx.alienvault.com/api/v1/pulses/subscribed
# Source Format: MISP Feed
# Distribution: Your organization only

# Fetch and import
curl -X POST https://your-misp-instance.com/feeds/fetchFromFeed/[feed_id] \
  -H "Authorization: YOUR_API_KEY" \
  -H "Accept: application/json"
```

**Search and export IOCs:**
```python
from pymisp import PyMISP
import json

misp = PyMISP('https://your-misp-instance.com', 'YOUR_API_KEY', ssl=True)

# Search for recent IP addresses
result = misp.search(
    controller='attributes',
    type_attribute='ip-dst',
    timestamp='7d',  # Last 7 days
    to_ids=True,     # Only indicators
    pythonify=True
)

# Export to CSV for firewall blocking
with open('blocklist.csv', 'w') as f:
    f.write('ip_address,first_seen,comment\n')
    for attr in result['Attribute']:
        f.write(f"{attr.value},{attr.timestamp},{attr.comment}\n")

print(f"Exported {len(result['Attribute'])} IP addresses")
```

**Automate indicator enrichment:**
```python
from pymisp import PyMISP

misp = PyMISP('https://your-misp-instance.com', 'YOUR_API_KEY', ssl=True)

# Enable enrichment modules
# Configure at: Administration > Server Settings > Plugin Settings

# Enrich an attribute with VirusTotal
event_id = 123
attribute_id = 456

result = misp.enrich(
    module='virustotal',
    event_id=event_id,
    attribute_id=attribute_id
)

print(f"Enrichment results: {result}")
```

**Integration with Splunk:**
```python
# Export MISP events to Splunk
import requests
from pymisp import PyMISP

misp = PyMISP('https://your-misp-instance.com', 'YOUR_API_KEY', ssl=True)

# Get recent events
events = misp.search(
    timestamp='24h',
    published=True,
    pythonify=True
)

# Send to Splunk HEC
splunk_hec_url = 'https://splunk:8088/services/collector/event'
splunk_token = 'YOUR_HEC_TOKEN'

for event in events:
    payload = {
        'event': event.to_dict(),
        'sourcetype': 'misp:event',
        'source': 'misp'
    }
    
    requests.post(
        splunk_hec_url,
        headers={'Authorization': f'Splunk {splunk_token}'},
        json=payload,
        verify=False
    )
```

### Best Practices

- **Data Quality** - Validate indicators before sharing; remove false positives
- **Classification** - Use TLP (Traffic Light Protocol) and PAP (Permissible Actions Protocol)
- **Contextualization** - Add comments, tags, and relationships to indicators
- **Regular Maintenance** - Prune old events and update feed sources
- **Access Control** - Use sharing groups for controlled distribution
- **API Rate Limiting** - Implement throttling for automated queries
- **Backup Strategy** - Regular database backups and disaster recovery plans

<br>
<br>

## OpenCTI (Open Cyber Threat Intelligence)
OpenCTI is a modern, knowledge graph-based threat intelligence platform that provides advanced analysis capabilities for understanding complex threat actor relationships, campaigns, and attack patterns. It uses STIX 2.1 as its data model.

### Key Features

- **Knowledge Graph** - Visualize complex relationships between entities
- **STIX 2.1 Native** - Standards-compliant data modeling
- **Connector Ecosystem** - Import from 100+ threat intelligence sources
- **Advanced Analysis** - Graph algorithms for pattern detection
- **Collaborative Workspaces** - Team-based intelligence analysis
- **Custom Dashboards** - Tailored views for different stakeholders
- **Kill Chain Mapping** - Track adversary progression through attack lifecycle

### Installation & Setup

**Using Docker Compose (Production):**
```bash
# Clone OpenCTI repository
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker

# Configure environment
nano .env

# Key configurations to set:
# OPENCTI_ADMIN_EMAIL=admin@opencti.io
# OPENCTI_ADMIN_PASSWORD=ChangeMeNow!
# OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
# OPENCTI_BASE_URL=http://localhost:8080

# Start services
docker-compose up -d

# Verify services are running
docker-compose ps

# Access OpenCTI
# URL: http://localhost:8080
# Login with credentials from .env
```

**Minimum System Requirements:**
- 4 CPU cores
- 8 GB RAM (16 GB recommended)
- 50 GB storage (SSD recommended)
- Docker 20.10+ and Docker Compose 2.0+

**Initial Configuration:**
```bash
# Access Settings > Parameters
# Configure:
# - Platform URL
# - Email notifications (SMTP)
# - Session timeout
# - Maximum file upload size

# Enable connectors for data import
# Navigate to: Data > Connectors
# Activate desired connectors (AlienVault, MISP, etc.)
```

### Architecture Components

```
OpenCTI Platform
├── Frontend (React) - User interface
├── Backend (Node.js) - API and business logic
├── Worker (Python) - Background tasks and connectors
├── Redis - Caching and message queue
├── ElasticSearch - Full-text search
├── MinIO - File storage
└── RabbitMQ - Message broker
```

### Practical Examples

**Create a threat actor profile:**
```python
from pycti import OpenCTIApiClient
from datetime import datetime

# Initialize OpenCTI client
api = OpenCTIApiClient(
    url='http://localhost:8080',
    token='YOUR_API_TOKEN'
)

# Create threat actor
threat_actor = api.threat_actor.create(
    name='APT29',
    description='Russian advanced persistent threat group',
    aliases=['Cozy Bear', 'The Dukes'],
    sophistication='advanced',
    resource_level='government',
    primary_motivation='intelligence-gathering',
    goals=['Espionage', 'Data theft'],
    first_seen=datetime(2008, 1, 1).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
    country='Russia'
)

print(f"Created threat actor: {threat_actor['name']} (ID: {threat_actor['id']})")
```

**Model an attack campaign:**
```python
from pycti import OpenCTIApiClient

api = OpenCTIApiClient(url='http://localhost:8080', token='YOUR_API_TOKEN')

# Create campaign
campaign = api.campaign.create(
    name='SolarWinds Supply Chain Attack',
    description='Sophisticated supply chain compromise targeting SolarWinds Orion',
    objective='Long-term espionage and credential theft',
    first_seen='2020-03-01T00:00:00.000Z',
    last_seen='2020-12-13T00:00:00.000Z'
)

# Link campaign to threat actor
api.stix_core_relationship.create(
    fromId=threat_actor['id'],
    toId=campaign['id'],
    relationship_type='attributed-to',
    confidence=85,
    description='High confidence attribution based on TTPs and infrastructure'
)

# Add targeted sectors
sectors = ['government', 'technology', 'finance']
for sector in sectors:
    sector_obj = api.identity.create(
        name=f"{sector.capitalize()} Sector",
        identity_class='class',
        type='identity'
    )
    
    api.stix_core_relationship.create(
        fromId=campaign['id'],
        toId=sector_obj['id'],
        relationship_type='targets',
        confidence=90
    )
```

**Import STIX bundle:**
```python
import json
from pycti import OpenCTIApiClient

api = OpenCTIApiClient(url='http://localhost:8080', token='YOUR_API_TOKEN')

# Load STIX bundle from file
with open('threat_report.json', 'r') as f:
    stix_bundle = json.load(f)

# Import bundle
result = api.stix2.import_bundle_from_json(stix_bundle)

print(f"Imported {len(result)} objects")
```

**Query and visualize infrastructure:**
```python
from pycti import OpenCTIApiClient

api = OpenCTIApiClient(url='http://localhost:8080', token='YOUR_API_TOKEN')

# Find all infrastructure used by a threat actor
infrastructure = api.stix_domain_object.list(
    types=['Infrastructure'],
    filters=[{
        'key': 'createdBy',
        'values': [threat_actor['id']]
    }]
)

# Get relationships
for infra in infrastructure:
    relationships = api.stix_core_relationship.list(
        fromId=infra['id'],
        relationship_type='communicates-with'
    )
    
    print(f"Infrastructure: {infra['name']}")
    print(f"  Connected to: {len(relationships)} entities")
    
    # Export graph for visualization
    graph_data = api.stix_domain_object.export_graph(
        entity_id=infra['id'],
        export_type='simple',
        max_level=2
    )
```

**Automated threat report ingestion:**
```python
from pycti import OpenCTIApiClient
import feedparser

api = OpenCTIApiClient(url='http://localhost:8080', token='YOUR_API_TOKEN')

# Parse RSS feed
feed_url = 'https://www.cisa.gov/uscert/ncas/alerts.xml'
feed = feedparser.parse(feed_url)

for entry in feed.entries[:5]:  # Process latest 5
    # Create report object
    report = api.report.create(
        name=entry.title,
        description=entry.summary,
        published=entry.published,
        report_types=['threat-report'],
        confidence=70,
        external_references=[{
            'source_name': 'CISA Alert',
            'url': entry.link
        }]
    )
    
    print(f"Created report: {report['name']}")
```

**Integration with SIEM:**
```python
from pycti import OpenCTIApiClient
import requests

api = OpenCTIApiClient(url='http://localhost:8080', token='YOUR_API_TOKEN')

# Get recent indicators
indicators = api.indicator.list(
    first=100,
    filters=[{
        'key': 'created_at',
        'values': ['2024-01-01T00:00:00.000Z'],
        'operator': 'gt'
    }]
)

# Push to SIEM (example: Splunk)
splunk_hec = 'https://splunk:8088/services/collector/event'
splunk_token = 'YOUR_HEC_TOKEN'

for indicator in indicators:
    event = {
        'event': {
            'indicator': indicator['pattern'],
            'type': indicator['pattern_type'],
            'confidence': indicator.get('confidence', 'unknown'),
            'valid_from': indicator.get('valid_from'),
            'labels': indicator.get('labels', [])
        },
        'sourcetype': 'opencti:indicator'
    }
    
    requests.post(
        splunk_hec,
        headers={'Authorization': f'Splunk {splunk_token}'},
        json=event,
        verify=False
    )
```

### Best Practices

- **Data Modeling** - Use consistent entity types and relationships
- **Confidence Scores** - Always assign confidence levels to relationships
- **Source Attribution** - Track data provenance with external references
- **Regular Updates** - Keep connectors active for fresh intelligence
- **Access Control** - Implement role-based access for sensitive intelligence
- **Performance** - Monitor ElasticSearch and optimize queries for large datasets
- **Backup** - Regular backups of ElasticSearch indices and PostgreSQL database

<br>
<br>

## MITRE ATT&CK Framework
MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It's the de facto standard for understanding adversary behavior.

> * Check this repo:
>   * https://github.com/Galeax/CVE2CAPEC

### Framework Structure

**Matrices:**
- **Enterprise** - Windows, macOS, Linux, Cloud (AWS, Azure, GCP)
- **Mobile** - Android, iOS
- **ICS** - Industrial Control Systems

**Components:**
- **Tactics** - "Why" - adversary goals (Initial Access, Execution, etc.)
- **Techniques** - "How" - methods to achieve tactical goals
- **Sub-techniques** - Specific variations of techniques
- **Procedures** - Real-world examples from threat groups
- **Mitigations** - Defensive measures
- **Data Sources** - Log sources for detection

### Practical Examples

**Map incident to ATT&CK:**
```yaml
# Incident: Ransomware attack via phishing

# Initial Access
T1566.001:  # Phishing: Spearphishing Attachment
  - Observed: Malicious PDF attachment
  - Detection: Email gateway blocked 15 similar emails
  - Evidence: Email logs, sandbox analysis

# Execution  
T1204.002:  # User Execution: Malicious File
  - Observed: User opened attachment, macro executed
  - Detection: EDR detected macro execution
  - Evidence: Process creation logs, EDR telemetry

# Defense Evasion
T1027:      # Obfuscated Files or Information
  - Observed: Macro used XOR encoding
  - Detection: Static analysis revealed encoding
  - Evidence: Malware sample, YARA rule match

# Credential Access
T1003.001:  # OS Credential Dumping: LSASS Memory
  - Observed: Mimikatz dumped credentials
  - Detection: LSASS process access alert
  - Evidence: Memory dumps, Sysmon Event ID 10

# Lateral Movement
T1021.001:  # Remote Desktop Protocol
  - Observed: RDP used to spread to 5 systems
  - Detection: Unusual RDP connections
  - Evidence: Windows Security Event ID 4624

# Impact
T1486:      # Data Encrypted for Impact
  - Observed: 2,000+ files encrypted
  - Detection: High volume file modifications
  - Evidence: Ransomware note, encrypted files
```

**Create detection coverage matrix:**
```python
import json
import requests

# ATT&CK STIX data
attack_url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
response = requests.get(attack_url)
attack_data = response.json()

# Extract techniques
techniques = [
    obj for obj in attack_data['objects']
    if obj['type'] == 'attack-pattern'
]

# Your detection coverage (example)
detections = {
    'T1566.001': {'coverage': 'high', 'tools': ['Email Gateway', 'Sandbox']},
    'T1204.002': {'coverage': 'high', 'tools': ['EDR', 'Application Control']},
    'T1027': {'coverage': 'medium', 'tools': ['Static Analysis', 'YARA']},
    'T1003.001': {'coverage': 'high', 'tools': ['EDR', 'Sysmon']},
    'T1021.001': {'coverage': 'medium', 'tools': ['Network Monitor', 'SIEM']},
    'T1486': {'coverage': 'medium', 'tools': ['EDR', 'File Monitoring']}
}

# Generate coverage report
coverage_report = {
    'total_techniques': len(techniques),
    'covered': len(detections),
    'coverage_percentage': (len(detections) / len(techniques)) * 100,
    'by_tactic': {}
}

for tech in techniques:
    if 'external_references' in tech:
        tech_id = next(
            (ref['external_id'] for ref in tech['external_references'] 
             if ref.get('source_name') == 'mitre-attack'),
            None
        )
        
        if tech_id in detections:
            tactic = tech.get('kill_chain_phases', [{}])[0].get('phase_name', 'unknown')
            if tactic not in coverage_report['by_tactic']:
                coverage_report['by_tactic'][tactic] = {'total': 0, 'covered': 0}
            
            coverage_report['by_tactic'][tactic]['covered'] += 1
        
        # Count all techniques by tactic
        for phase in tech.get('kill_chain_phases', []):
            tactic = phase.get('phase_name', 'unknown')
            if tactic not in coverage_report['by_tactic']:
                coverage_report['by_tactic'][tactic] = {'total': 0, 'covered': 0}
            coverage_report['by_tactic'][tactic]['total'] += 1

print(json.dumps(coverage_report, indent=2))
```

**Generate threat profile for APT group:**
```python
import requests
import json

# Fetch ATT&CK data
attack_url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
response = requests.get(attack_url)
attack_data = response.json()

# Get APT29 (Cozy Bear) techniques
apt29_techniques = []

for obj in attack_data['objects']:
    if obj['type'] == 'relationship' and obj.get('relationship_type') == 'uses':
        # Check if source is APT29
        source_ref = obj.get('source_ref', '')
        if 'apt29' in source_ref.lower() or 'cozy-bear' in source_ref.lower():
            apt29_techniques.append({
                'technique': obj.get('target_ref'),
                'description': obj.get('description', 'No description')
            })

# Create defensive playbook
playbook = {
    'threat_actor': 'APT29',
    'priority': 'critical',
    'techniques_count': len(apt29_techniques),
    'focus_areas': [
        'Cloud environment monitoring',
        'OAuth application abuse detection',
        'Sophisticated phishing defenses',
        'Legitimate credential usage monitoring'
    ],
    'recommended_detections': []
}

# Map to Sigma rules or custom detection logic
print(json.dumps(playbook, indent=2))
```

### ATT&CK Navigator

**Using the Navigator:**
```json
{
  "name": "SOC Detection Coverage",
  "versions": {
    "attack": "14",
    "navigator": "4.9",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Current detection coverage for Enterprise tactics",
  "techniques": [
    {
      "techniqueID": "T1566.001",
      "color": "#00ff00",
      "comment": "Email gateway + sandbox + user training",
      "score": 95
    },
    {
      "techniqueID": "T1003.001",
      "color": "#00ff00",
      "comment": "EDR + Sysmon + honeypots",
      "score": 90
    },
    {
      "techniqueID": "T1021.001",
      "color": "#ffff00",
      "comment": "Network monitoring + baseline",
      "score": 60
    },
    {
      "techniqueID": "T1486",
      "color": "#ff9900",
      "comment": "File monitoring + backups",
      "score": 45
    }
  ],
  "gradient": {
    "colors": [
      "#ff0000",
      "#ffff00",
      "#00ff00"
    ],
    "minValue": 0,
    "maxValue": 100
  },
  "legendItems": [
    {"label": "High Coverage (75-100)", "color": "#00ff00"},
    {"label": "Medium Coverage (50-74)", "color": "#ffff00"},
    {"label": "Low Coverage (25-49)", "color": "#ff9900"},
    {"label": "No Coverage (0-24)", "color": "#ff0000"}
  ]
}
```

**Load this layer:**
1. Visit https://mitre-attack.github.io/attack-navigator/
2. Click "Open Existing Layer" → "Upload from local"
3. Upload JSON file
4. Visualize your detection coverage

### Integration Examples

**Export ATT&CK data to MISP:**
```python
from pymisp import PyMISP
import requests

# Get ATT&CK techniques
attack_url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
attack_data = requests.get(attack_url).json()

# Connect to MISP
misp = PyMISP('https://your-misp-instance.com', 'YOUR_API_KEY', ssl=True)

# Import ATT&CK Galaxy
for obj in attack_data['objects']:
    if obj['type'] == 'attack-pattern':
        # Extract technique details
        tech_id = next(
            (ref['external_id'] for ref in obj.get('external_references', [])
             if ref.get('source_name') == 'mitre-attack'),
            None
        )
        
        if tech_id:
            # Add as MISP galaxy
            misp.add_galaxy_cluster(
                galaxy_id='attack-pattern',
                value=f"{tech_id} - {obj['name']}",
                description=obj.get('description', ''),
                source='MITRE ATT&CK'
            )
```

**Generate Sigma rules for technique:**
```yaml
# Sigma rule template for T1003.001 - LSASS Credential Dumping

title: Suspicious LSASS Process Access
id: 32d0d3e2-e58d-4d41-926d-3b4f9e547fcb
status: stable
description: Detects process access to LSASS which may indicate credential dumping
author: SOC Team
references:
  - https://attack.mitre.org/techniques/T1003/001/
date: 2024/01/12
modified: 2024/01/12
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  service: sysmon
  definition: Sysmon Event ID 10
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1410'
      - '0x1438'
      - '0x143a'
  filter_legitimate:
    SourceImage|endswith:
      - '\wmiprvse.exe'
      - '\taskmgr.exe'
      - '\procexp64.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate administrative tools
  - Security software
level: high
```

### Best Practices

- **Regular Updates** - ATT&CK is updated twice yearly; review changes
- **Context Matters** - Map techniques with confidence scores and evidence
- **Coverage Gaps** - Use matrices to identify detection blind spots
- **Threat-Informed Defense** - Prioritize defenses based on relevant threat actors
- **Team Training** - Ensure analysts understand ATT&CK terminology
- **Tool Integration** - Embed ATT&CK in SIEM, EDR, and threat intel platforms
- **Purple Team Exercises** - Use ATT&CK to guide adversary emulation

<br>
<br>

## Intelligence Sources & Feeds

### Commercial Providers
- **Recorded Future** - Real-time threat intelligence
- **CrowdStrike Falcon Intelligence** - Adversary intelligence
- **Mandiant Threat Intelligence** - APT tracking and analysis
- **Anomali ThreatStream** - Aggregated threat feeds
- **ThreatConnect** - Intelligence operations platform

### Open Source Feeds
- **AlienVault OTX** - Community-driven threat exchange
- **Abuse.ch** - Malware samples and IOCs (URLhaus, MalwareBazaar)
- **PhishTank** - Phishing URL database
- **Spamhaus** - IP and domain reputation
- **Cybercrime-Tracker** - C2 panel tracking
- **ThreatFox** - IOC sharing platform

### Government Sources
- **CISA Alerts** - US government cybersecurity advisories
- **FBI Flash Alerts** - Law enforcement threat notifications
- **NCSC Advisories** - UK cybersecurity guidance
- **CERT/CC Vulnerability Notes** - Vulnerability coordination

### Industry Sharing Groups
- **ISACs** - Information Sharing and Analysis Centers (sector-specific)
- **FS-ISAC** - Financial Services
- **H-ISAC** - Healthcare
- **E-ISAC** - Energy
- **ASAC** - Automotive

<br>
<br>

## Operationalizing Threat Intelligence

### Integration Architecture

```
┌─────────────────────────────────────────────────────┐
│            Threat Intelligence Platform             │
│                 (MISP / OpenCTI)                    │
└────────────────┬────────────────────────────────────┘
                 │
         ┌───────┴────────┐
         │                │
    ┌────▼────┐      ┌────▼────┐
    │Firewall │      │ Email   │
    │         │      │ Gateway │
    └─────────┘      └─────────┘
```

### Tactical Implementation

**Phase 1 - Foundation (Weeks 1-4):**
- Deploy MISP or OpenCTI instance
- Configure initial threat feeds (start with 3-5 high-quality sources)
- Establish tagging taxonomy and classification scheme
- Train SOC team on platform usage

**Phase 2 - Integration (Weeks 5-8):**
- Connect TIP to SIEM for automated alerting
- Integrate with EDR for endpoint IOC checking
- Configure firewall/IPS for automated blocking
- Implement API-based IOC enrichment

**Phase 3 - Operationalization (Weeks 9-12):**
- Develop standard operating procedures for intelligence consumption
- Create automated playbooks for indicator response
- Establish metrics for intelligence effectiveness
- Begin threat actor tracking and TTP mapping

**Phase 4 - Maturation (Ongoing):**
- Join intelligence sharing communities
- Contribute original research and analysis
- Implement threat hunting based on intelligence
- Continuous improvement based on feedback

### Key Performance Indicators (KPIs)

**Input Metrics:**
- Number of intelligence sources consumed
- Volume of indicators processed daily
- Feed reliability scores
- Time to ingest new intelligence

**Process Metrics:**
- Mean time to enrich indicators
- False positive rate
- Analyst time spent on manual enrichment
- Indicator correlation success rate

**Output Metrics:**
- Alerts generated from TI
- Threats blocked proactively
- Mean time to detection improvement
- Incident response time reduction

### Automation Examples

**Automated IOC Blocking:**
```python
from pymisp import PyMISP
import requests

misp = PyMISP('https://misp.local', 'API_KEY', ssl=True)

# Get high-confidence malicious IPs from last 24 hours
indicators = misp.search(
    controller='attributes',
    type_attribute='ip-dst',
    timestamp='24h',
    to_ids=True,
    tags='confidence:high',
    pythonify=True
)

# Push to firewall (example: Palo Alto)
firewall_api = 'https://firewall.local/api'
firewall_key = 'FIREWALL_API_KEY'

for indicator in indicators:
    # Add to block list
    payload = {
        'type': 'config',
        'action': 'set',
        'xpath': f'/config/devices/entry/vsys/entry/address/entry[@name="{indicator.value}"]',
        'element': f'<ip-netmask>{indicator.value}</ip-netmask>'
    }
    
    requests.post(
        firewall_api,
        params={'key': firewall_key, **payload},
        verify=False
    )

print(f"Blocked {len(indicators)} malicious IPs")
```

**Threat Hunting Trigger:**
```python
from pymisp import PyMISP
import smtplib
from email.mime.text import MIMEText

misp = PyMISP('https://misp.local', 'API_KEY', ssl=True)

# Monitor for new APT activity
events = misp.search(
    controller='events',
    timestamp='1h',
    tags=['misp-galaxy:threat-actor="APT29"', 'misp-galaxy:threat-actor="APT28"'],
    pythonify=True
)

if events:
    # Trigger threat hunt
    hunt_team_email = 'threathunt@company.com'
    
    message = MIMEText(
        f"New APT activity detected!\n\n"
        f"Events: {len(events)}\n"
        f"Recommendation: Initiate proactive threat hunt for related TTPs\n\n"
        f"MISP Event IDs: {[e.id for e in events]}"
    )
    
    message['Subject'] = '[URGENT] APT Activity Detected - Threat Hunt Required'
    message['From'] = 'ti-platform@company.com'
    message['To'] = hunt_team_email
    
    smtp = smtplib.SMTP('smtp.company.com')
    smtp.send_message(message)
    smtp.quit()
```

<br>

## Threat Intelligence Maturity Model

### Level 0 - Initial
- Ad-hoc intelligence consumption
- No formal processes
- Reactive posture only

### Level 1 - Defined
- Basic threat feeds implemented
- TIP deployed
- Intelligence shared within security team
- Manual indicator processing

### Level 2 - Managed
- Automated indicator ingestion and enrichment
- Integration with detection platforms
- Regular intelligence reports
- Participation in sharing communities

### Level 3 - Optimized
- Proactive threat hunting driven by intelligence
- Custom threat actor tracking
- Strategic intelligence for executive reporting
- Automated response workflows
- Contribution to threat intelligence community

### Level 4 - Advanced
- Predictive threat modeling
- Machine learning-enhanced analysis
- Original threat research publication
- Industry leadership in intelligence sharing
- Full automation of tactical intelligence lifecycle

<br>

## Training Resources

### Certifications
- **GIAC Cyber Threat Intelligence (GCTI)** - Foundational CTI certification
- **CREST Certified Threat Intelligence Manager (CCTIM)** - Management focus
- **Certified Threat Intelligence Analyst (CTIA)** - Analyst-level certification

### Online Courses
- **SANS FOR578** - Cyber Threat Intelligence
- **Recorded Future Intelligence Fundamentals** - Free training
- **MITRE ATT&CK Defender** - Free ATT&CK training

### Books
- "Intelligence-Driven Incident Response" by Scott Roberts & Rebekah Brown
- "Threat Intelligence Handbook" by Recorded Future
- "The Art of Cyber Threat Intelligence" by Franck Ebel

### Communities
- **MISP Project** - Community forums and documentation
- **OpenCTI Community** - Slack channel and GitHub discussions
- **ATT&CK Community** - MITRE's community forums
- **CTI League** - Volunteer threat intelligence sharing

<br>

## Common Challenges & Solutions

### Challenge 1: Information Overload
**Problem:** Too many indicators, not enough context
**Solution:** 
- Implement confidence scoring and prioritization
- Use automated enrichment
- Focus on high-fidelity sources
- Filter by relevance to your environment

### Challenge 2: Alert Fatigue
**Problem:** High volume of low-quality alerts from TI feeds
**Solution:**
- Tune feed sources regularly
- Implement progressive blocking (monitor → alert → block)
- Use threat context to prioritize
- Establish clear escalation criteria

### Challenge 3: Stale Intelligence
**Problem:** Old indicators creating false positives
**Solution:**
- Implement TTL (Time To Live) for indicators
- Regular feed maintenance and cleanup
- Validate indicators before acting
- Use sighting data to update confidence

### Challenge 4: Lack of Actionability
**Problem:** Intelligence doesn't translate to defensive actions
**Solution:**
- Map intelligence to MITRE ATT&CK
- Create detection engineering workflows
- Develop standard response playbooks
- Include defensive recommendations in reports

### Challenge 5: Siloed Intelligence
**Problem:** Intelligence not shared across teams
**Solution:**
- Centralized TIP for all teams
- Regular cross-functional meetings
- Automated dissemination workflows
- Executive-level strategic reports

<br>

## Additional Resources

### Threat Intelligence Frameworks
- **STIX/TAXII** - Structured Threat Information eXpression
- **Diamond Model** - Adversary analysis framework
- **Kill Chain** - Lockheed Martin attack progression model
- **Cyber Kill Chain** - Attack lifecycle mapping

### Useful Tools
- **TheHive** - Security incident response platform
- **Cortex** - Observable analysis and enrichment
- **YETI** - Threat intelligence repository
- **IntelMQ** - Automated IOC processing
- **ThreatConnect** - Threat intelligence aggregation

### Data Standards
- **STIX 2.1** - Cyber threat information representation
- **TAXII 2.1** - Threat information sharing protocol
- **CybOX** - Cyber Observable eXpression (legacy)
- **IODEF** - Incident Object Description Exchange Format
- **VERIS** - Vocabulary for Event Recording and Incident Sharing

### API Documentation
- [MISP API Documentation](https://www.misp-project.org/openapi/)
- [OpenCTI Python Library](https://github.com/OpenCTI-Platform/client-python)
- [ATT&CK API](https://github.com/mitre-attack/attack-stix-data)

<br>

## Best Practices Summary

**Do:**
- Start small with high-quality sources
- Automate repetitive enrichment tasks
- Validate intelligence before acting
- Share intelligence with trusted partners
- Map intelligence to defensive controls
- Measure effectiveness with KPIs
- Regular training for analysts

**Don't:**
- Block indicators without validation
- Ignore context and confidence scores
- Neglect feed maintenance
- Operate in isolation from the community
- Overlook strategic intelligence value
- Skip threat modeling exercises
- Forget to document processes

<br>

---

<br>
<br>

<div align="center">

| ← Previous Page | Home | Next Phase → |
|:-----------|:----:|-------:|
| [Preparation](./1.0-Preparation.md) | [Landing Page](../../README.md) | [Detection and Analysis](../2-Detection-and-Analysis/2.0-Detection-and-Analysis.md) |

</div>