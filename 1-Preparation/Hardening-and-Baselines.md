
# Hardening and Baselines

Establishing and maintaining secure configuration baselines is critical for defense-in-depth strategy. This guide covers industry-standard tools and methodologies for system hardening across operating systems, applications, and network infrastructure.

<br>

### Tools Reference Table

<p align=center>


| Tool | Purpose | Platform | Official Link |
|:-----|:--------|:---------|:--------------|
| [**CIS Benchmarks**](#cis-benchmarks) | Security configuration standards | Multi-platform | [cisecurity.org](https://www.cisecurity.org/cis-benchmarks/) |
| [**Group Policy**](#group-policy) | Centralized Windows policy management | Windows | [Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-group-policy-best-practices) |
| [**Ansible**](#ansible) | Automated configuration management | Multi-platform | [ansible.com](https://www.ansible.com/) |
| [**Chef**](#chef) | Infrastructure automation platform | Multi-platform | [chef.io](https://www.chef.io/) |

<br>
<br>

## CIS Benchmarks
The Center for Internet Security (CIS) provides consensus-based, best-practice security configuration guides for operating systems, cloud providers, network devices, and software applications. These benchmarks are developed by cybersecurity experts worldwide and represent industry standards for system hardening.

### Key Features

- Comprehensive coverage of major platforms (Windows, Linux, macOS, cloud services)
- Prescriptive guidance with rationale for each recommendation
- Two implementation levels: Level 1 (basic) and Level 2 (high security)
- Regular updates to address emerging threats

### Installation & Setup

```bash
# Download benchmarks from CIS website
# Visit: https://www.cisecurity.org/cis-benchmarks/
# Registration required (free for CIS benchmarks)

# For automated assessment, download CIS-CAT Pro or Lite
wget https://downloads.cisecurity.org/cis-cat-lite/latest
unzip cis-cat-lite.zip
cd cis-cat-lite
```

### Usage Guidelines

**Manual Implementation:**
1. Download the benchmark PDF for your target system
2. Review recommendations and select appropriate profile (Level 1 or Level 2)
3. Document baseline configuration decisions
4. Apply settings through native configuration tools
5. Validate implementation

**Automated Assessment:**
- Use CIS-CAT (Configuration Assessment Tool) for compliance scanning
- Generate reports showing compliance percentage
- Identify configuration gaps requiring remediation

### Practical Examples

**Run a compliance assessment:**
```bash
# Assess current system against CIS benchmark
cd Assessor
./Assessor-CLI.sh -i -rd /path/to/reports -rp cis-report

# Assess specific benchmark
./Assessor-CLI.sh -b benchmarks/CIS_Ubuntu_Linux_20.04_LTS_Benchmark_v1.0.0.xml
```

**Generate HTML report:**
```bash
java -jar Assessor-CLI.jar -a -html -rd /path/to/reports
```

### Best Practices

- Start with Level 1 recommendations and test thoroughly
- Document exceptions and their business justification
- Schedule regular compliance assessments (monthly/quarterly)
- Integrate with vulnerability management programs
- Review and update baselines when new versions are released

<br>

## Group Policy
Group Policy is a Windows infrastructure feature that provides centralized management and configuration of operating systems, applications, and user settings in an Active Directory environment. It's essential for enforcing security baselines across Windows domains.

### Key Features

- Centralized management of security policies
- Granular control over user and computer settings
- Policy inheritance and precedence rules
- Integration with Active Directory
- Audit and compliance reporting

### Installation & Setup

```powershell
# Group Policy is built into Windows Server and Active Directory
# No separate installation required

# Install Group Policy Management Console (GPMC) on Windows 10/11
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

# Verify installation
Get-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools*
```

### Common Security Policies

**Password Policies:**
- Password complexity requirements
- Minimum password length
- Password expiration settings
- Account lockout thresholds

**Audit Policies:**
- Logon/logoff events
- Object access auditing
- Policy change tracking
- Privilege use monitoring

**Security Options:**
- User rights assignments
- Security settings
- Registry permissions
- File system permissions

### Practical Examples

**Create a security baseline GPO:**
```powershell
# Create new GPO
New-GPO -Name "Security-Baseline-Servers" -Comment "CIS Level 1 baseline for member servers"

# Link to Organizational Unit
New-GPLink -Name "Security-Baseline-Servers" -Target "OU=Servers,DC=contoso,DC=com"

# Import security template
Restore-GPO -Name "Security-Baseline-Servers" -Path "C:\SecurityTemplates"
```

**Configure password policy via GUI:**
```
Group Policy Management Console (GPMC):
├── Computer Configuration
    └── Policies
        └── Windows Settings
            └── Security Settings
                └── Account Policies
                    └── Password Policy
                        ├── Password must meet complexity requirements: Enabled
                        ├── Minimum password length: 14 characters
                        ├── Maximum password age: 60 days
                        └── Enforce password history: 24 passwords
```

**Export GPO for backup:**
```powershell
# Backup specific GPO
Backup-GPO -Name "Security-Baseline-Servers" -Path "C:\GPOBackups"

# Backup all GPOs
Backup-GPO -All -Path "C:\GPOBackups"
```

**Generate GPO report:**
```powershell
# Generate HTML report
Get-GPOReport -Name "Security-Baseline-Servers" -ReportType Html -Path "C:\Reports\GPO-Report.html"

# Generate XML report
Get-GPOReport -All -ReportType Xml -Path "C:\Reports\All-GPOs.xml"
```

### Best Practices

- Test GPOs in a development OU before production deployment
- Document all custom GPO settings and their purpose
- Use security filtering to target specific groups
- Implement WMI filters for conditional policy application
- Monitor GPO processing with event logs (Event IDs 1502, 1503)
- Regular backup of all GPOs
- Use Resultant Set of Policy (RSoP) for troubleshooting

<br>

## Ansible
Ansible is an open-source automation platform for configuration management, application deployment, and task automation. It uses simple, human-readable YAML syntax and operates agentless, making it ideal for enforcing security baselines across diverse infrastructure.

### Key Features

- Agentless architecture (SSH-based)
- Declarative YAML playbooks
- Idempotent operations
- Extensive module library
- Role-based organization
- Integration with CI/CD pipelines

### Installation & Setup

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y ansible

# Verify installation
ansible --version
```

**RHEL/CentOS:**
```bash
sudo yum install -y epel-release
sudo yum install -y ansible
```

**Using pip:**
```bash
pip3 install ansible

# Install additional collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix
```

<!--### Structure

```
ansible-hardening/
├── ansible.cfg              # Ansible configuration
├── inventory/
│   ├── hosts               # Inventory file
│   └── group_vars/         # Group variables
├── playbooks/
│   ├── cis-hardening.yml   # Main playbook
│   └── remediate.yml       # Remediation playbook
├── roles/
│   ├── cis_benchmark/      # CIS baseline role
│   ├── ssh_hardening/      # SSH hardening role
│   └── audit_config/       # Audit configuration role
└── files/
    └── templates/          # Configuration templates
```-->

### Practical Examples

**Basic hardening playbook:**
```yaml
---
- name: Apply CIS Security Baseline
  hosts: linux_servers
  become: yes
  
  roles:
    - role: cis_benchmark
      cis_level: 1
    
  tasks:
    - name: Ensure SSH protocol 2 is used
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^Protocol'
        line: 'Protocol 2'
        state: present
      notify: restart sshd
    
    - name: Disable root login via SSH
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
        state: present
      notify: restart sshd
    
    - name: Set password complexity requirements
      lineinfile:
        path: /etc/security/pwquality.conf
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        state: present
      loop:
        - { regexp: '^minlen', line: 'minlen = 14' }
        - { regexp: '^dcredit', line: 'dcredit = -1' }
        - { regexp: '^ucredit', line: 'ucredit = -1' }
        - { regexp: '^lcredit', line: 'lcredit = -1' }
        - { regexp: '^ocredit', line: 'ocredit = -1' }
  
  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted
```

**Inventory file example:**
```ini
[linux_servers]
web01.example.com
web02.example.com
db01.example.com

[linux_servers:vars]
ansible_user=ansible
ansible_become=yes
ansible_become_method=sudo

[windows_servers]
win01.example.com
win02.example.com

[windows_servers:vars]
ansible_user=Administrator
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
```

**Run the playbook:**
```bash
# Execute hardening playbook
ansible-playbook -i inventory/hosts playbooks/cis-hardening.yml

# Check mode (dry run)
ansible-playbook -i inventory/hosts playbooks/cis-hardening.yml --check

# Limit to specific hosts
ansible-playbook -i inventory/hosts playbooks/cis-hardening.yml --limit web01.example.com

# Run with verbose output
ansible-playbook -i inventory/hosts playbooks/cis-hardening.yml -vvv
```

**Compliance checking playbook:**
```yaml
---
- name: Check CIS Compliance
  hosts: linux_servers
  become: yes
  
  tasks:
    - name: Check SSH configuration
      command: grep -E '^(Protocol|PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config
      register: ssh_config
      changed_when: false
    
    - name: Display SSH configuration
      debug:
        var: ssh_config.stdout_lines
    
    - name: Check firewall status
      command: systemctl status firewalld
      register: firewall_status
      changed_when: false
      failed_when: false
    
    - name: Report firewall status
      debug:
        msg: "Firewall is {{ 'active' if firewall_status.rc == 0 else 'inactive' }}"
```

### Using Ansible Roles from Ansible Galaxy

```bash
# Install pre-built CIS hardening role
ansible-galaxy install dev-sec.os-hardening

# Use in playbook
cat << EOF > playbooks/apply-hardening.yml
---
- name: Apply OS Hardening
  hosts: all
  become: yes
  roles:
    - dev-sec.os-hardening
EOF

# Run the playbook
ansible-playbook playbooks/apply-hardening.yml
```

### Best Practices

- Use version control (Git) for all Ansible code
- Implement idempotent playbooks (can run multiple times safely)
- Use Ansible Vault for sensitive data encryption
- Test playbooks in non-production environments first
- Leverage roles for reusability
- Use tags for selective execution
- Implement proper error handling and notifications
- Document playbooks with comments and README files

<br>

## Chef
Chef is a powerful infrastructure automation platform that uses Ruby-based DSL (Domain Specific Language) to define system configurations as code. It follows a client-server architecture and is well-suited for large-scale infrastructure management.

### Key Features

- Infrastructure as Code (IaC)
- Client-server architecture with Chef Server
- Recipe and cookbook organization
- Test-driven infrastructure development
- Integration with cloud platforms
- Compliance automation with InSpec

### Installation & Setup

**Chef Workstation (Development machine):**
```bash
# Ubuntu/Debian
wget https://packages.chef.io/files/stable/chef-workstation/latest/ubuntu/20.04/chef-workstation_latest_amd64.deb
sudo dpkg -i chef-workstation_latest_amd64.deb

# RHEL/CentOS
wget https://packages.chef.io/files/stable/chef-workstation/latest/el/8/chef-workstation-latest-1.el8.x86_64.rpm
sudo rpm -Uvh chef-workstation-latest-1.el8.x86_64.rpm

# Verify installation
chef --version
```

**Chef Client (Managed nodes):**
```bash
# Install Chef Infra Client
curl -L https://omnitruck.chef.io/install.sh | sudo bash

# Verify installation
chef-client --version
```

### Practical Examples

**Basic hardening cookbook structure:**
```ruby
# cookbooks/security_baseline/recipes/default.rb

# Disable root login via SSH
template '/etc/ssh/sshd_config' do
  source 'sshd_config.erb'
  owner 'root'
  group 'root'
  mode '0600'
  notifies :restart, 'service[sshd]'
end

service 'sshd' do
  action [:enable, :start]
end

# Configure firewall
firewall 'default' do
  action :install
end

firewall_rule 'ssh' do
  port 22
  protocol :tcp
  command :allow
end

# Set password policies
execute 'password_quality' do
  command <<-EOH
    sed -i 's/^minlen.*/minlen = 14/' /etc/security/pwquality.conf
    sed -i 's/^dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
  EOH
  not_if 'grep "^minlen = 14" /etc/security/pwquality.conf'
end
```

**Run Chef Client:**
```bash
# Execute single recipe
sudo chef-client --local-mode --runlist 'recipe[security_baseline]'

# Run with specific environment
sudo chef-client --environment production
```

**Compliance testing with InSpec:**
```ruby
# Test SSH configuration
control 'ssh-hardening' do
  impact 1.0
  title 'SSH Server Configuration'
  desc 'Ensure SSH is properly hardened'
  
  describe sshd_config do
    its('Protocol') { should eq '2' }
    its('PermitRootLogin') { should eq 'no' }
    its('PasswordAuthentication') { should eq 'no' }
  end
end

# Run InSpec profile
inspec exec /path/to/profile -t ssh://user@hostname
```

<br>

### Chef vs Ansible Quick Comparison

| Feature | Ansible | Chef |
|:--------|:--------|:-----|
| **Architecture** | Agentless (SSH) | Client-server (agent-based) |
| **Language** | YAML | Ruby DSL |
| **Learning Curve** | Easier | Steeper |
| **Best For** | Quick automation, smaller scale | Enterprise, complex infrastructure |
| **State Management** | Push-based | Pull-based |

<br>

## Comparison Matrix

| Aspect | CIS Benchmarks | Group Policy | Ansible | Chef |
|:-------|:--------------|:-------------|:--------|:-----|
| **Platform Coverage** | Multi-platform | Windows only | Multi-platform | Multi-platform |
| **Automation Level** | Manual + Tools | Built-in | High | High |
| **Learning Curve** | Low | Medium | Medium | High |
| **Cost** | Free (Pro tools paid) | Free (built-in) | Free (Tower paid) | Free (Server paid) |
| **Best Use Case** | Standards reference | Windows domains | Cross-platform automation | Enterprise IaC |

<br>

## Implementation Workflow

### 1. **Assessment Phase**
- Inventory all systems requiring hardening
- Identify applicable compliance frameworks (CIS, NIST, PCI-DSS)
- Document current baseline configurations
- Assess organizational risk tolerance

### 2. **Planning Phase**
- Select appropriate benchmark levels
- Define exceptions and compensating controls
- Choose automation tools based on infrastructure
- Create implementation timeline

### 3. **Implementation Phase**
- Deploy configurations in test environment
- Validate functionality and compatibility
- Create rollback procedures
- Document all changes

### 4. **Validation Phase**
- Run compliance scans (CIS-CAT, OpenSCAP)
- Verify no operational impact
- Test application compatibility
- Review security logs

### 5. **Maintenance Phase**
- Schedule regular compliance assessments
- Monitor for configuration drift
- Update baselines with new benchmarks
- Conduct periodic reviews and updates

<br>

## Additional Resources

### Official Documentation
- [CIS Controls](https://www.cisecurity.org/controls/)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [Ansible Documentation](https://docs.ansible.com/)
- [Chef Documentation](https://docs.chef.io/)

### Community Resources
- [Ansible Galaxy](https://galaxy.ansible.com/) - Pre-built roles and collections
- [Chef Supermarket](https://supermarket.chef.io/) - Community cookbooks
- [STIGs (Security Technical Implementation Guides)](https://public.cyber.mil/stigs/)
- [DevSec Hardening Framework](https://dev-sec.io/)

### Recommended Tools
- **OpenSCAP** - Open-source compliance scanning
- **Lynis** - Security auditing tool for Unix/Linux
- **Windows Security Compliance Toolkit** - Microsoft's security baseline tools
- **Terraform** - Infrastructure provisioning (complements configuration management)

<br>

## Important Considerations

**Before Implementing Hardening:**
- Always test in non-production environments first
- Document baseline configurations before changes
- Ensure proper change management procedures
- Have rollback plans ready
- Consider application compatibility
- Coordinate with application owners
- Schedule maintenance windows appropriately

**Common Pitfalls to Avoid:**
- Applying Level 2 CIS recommendations without testing
- Neglecting to document exceptions
- Failing to account for legacy application requirements
- Not monitoring for configuration drift
- Ignoring operational impact assessments

<br>

---

<br>
<br>

<div align="center">

| ← Previous Page | Home | Next Phase → |
|:-----------|:----:|-------:|
| [Preparation](./1.0-Preparation.md) | [Landing Page](../../README.md) | [Detection and Analysis](../2-Detection-and-Analysis/2.0-Detection-and-Analysis.md) |

</div>