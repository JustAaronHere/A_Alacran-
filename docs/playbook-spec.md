# Revenant Playbook Specification

## Overview

Playbooks are YAML-based automation scripts that define sequences of actions for incident response, remediation, and verification. They support conditionals, approvals, rollbacks, and variable substitution.

## Playbook Structure

```yaml
name: string              # Playbook identifier (required)
version: string           # Semantic version (required)
description: string       # Human-readable description
author: string            # Playbook author
tags: []string            # Classification tags

# Trigger configuration
triggers:
  - event_type: string    # Event type that triggers this playbook
    conditions: {}        # Condition matching

# Variables with defaults
variables:
  key: value

# Pre-execution checks
preconditions:
  - check: string         # Check to perform
    params: {}

# Main execution steps
steps:
  - name: string          # Step identifier
    type: string          # Action type
    action: string        # Specific action
    target: string        # Target resource
    params: {}            # Action parameters
    on_failure: string    # continue | rollback | abort
    approval_required: bool
    timeout: duration

# Post-execution verification
postconditions:
  - verify: string
    params: {}

# Rollback steps (reverse order)
rollback:
  - name: string
    type: string
    action: string
    params: {}

# Metadata
metadata:
  severity: string        # low | medium | high | critical
  category: string        # containment | remediation | forensics
  rbac_role: string       # Required role to execute
  audit: bool             # Enable detailed auditing
```

## Action Types

### 1. Containment Actions

**isolate_host**
```yaml
- name: Isolate compromised host
  type: containment
  action: isolate_host
  target: ${host_id}
  params:
    method: nac           # nac | firewall | edr
    reason: "Malware detected"
```

**block_ip**
```yaml
- name: Block malicious IP
  type: containment
  action: block_ip
  target: ${ip_address}
  params:
    direction: inbound    # inbound | outbound | both
    duration: 3600        # seconds, 0 for permanent
```

**quarantine_device**
```yaml
- name: Quarantine device via NAC
  type: containment
  action: quarantine
  target: ${mac_address}
  params:
    provider: cisco_ise   # cisco_ise | aruba_clearpass
    vlan_id: 999          # Quarantine VLAN
```

**disable_port**
```yaml
- name: Disable switch port
  type: containment
  action: disable_port
  target: ${switch_ip}
  params:
    port: ${switch_port}
```

### 2. EDR Actions

**kill_process**
```yaml
- name: Kill malicious process
  type: edr
  action: kill_process
  target: ${host_id}
  params:
    process_id: ${pid}
    process_name: ${process_name}
    force: true
```

**collect_forensics**
```yaml
- name: Collect host forensics
  type: edr
  action: collect_forensics
  target: ${host_id}
  params:
    artifacts:
      - memory_dump
      - process_list
      - network_connections
      - file_hashes
    upload_to: ${storage_url}
```

### 3. Cloud Actions

**isolate_instance**
```yaml
- name: Isolate AWS EC2 instance
  type: cloud
  action: isolate_instance
  target: ${instance_id}
  params:
    provider: aws
    region: ${region}
    security_group: sg-quarantine
```

**snapshot_volume**
```yaml
- name: Snapshot volume for forensics
  type: cloud
  action: snapshot_volume
  target: ${volume_id}
  params:
    provider: azure
    tags:
      incident_id: ${incident_id}
      timestamp: ${timestamp}
```

### 4. Notification Actions

**send_alert**
```yaml
- name: Notify security team
  type: notification
  action: send_alert
  params:
    channels:
      - slack
      - email
      - pagerduty
    message: "Critical incident: ${incident_description}"
    priority: critical
```

**create_ticket**
```yaml
- name: Create Jira ticket
  type: ticketing
  action: create_ticket
  params:
    provider: jira
    project: SEC
    issue_type: Incident
    priority: high
    summary: "Security incident: ${incident_id}"
    description: ${incident_details}
    assignee: security-team
```

### 5. Verification Actions

**rescan_host**
```yaml
- name: Re-scan host post-remediation
  type: verification
  action: rescan
  target: ${host_ip}
  params:
    scanner: aegis
    mode: comprehensive
    check_vulns: true
```

**verify_isolation**
```yaml
- name: Verify host is isolated
  type: verification
  action: verify_isolation
  target: ${host_id}
  params:
    method: connectivity_test
    expected: no_connectivity
```

### 6. Sandbox Actions

**sandbox_verify**
```yaml
- name: Verify exploit in sandbox
  type: sandbox
  action: verify
  params:
    image: ubuntu:20.04
    script: ${verification_script}
    timeout: 300
    network: isolated
```

### 7. Custom Command Actions

**execute_command**
```yaml
- name: Run custom remediation script
  type: command
  action: execute
  target: ${host_id}
  params:
    command: /opt/remediation/fix-vulnerability.sh
    args: ["--host", "${host_ip}"]
    user: root
    timeout: 600
```

## Conditional Execution

Use `conditions` to control step execution:

```yaml
- name: Escalate if critical
  type: notification
  action: send_alert
  conditions:
    - severity == "critical"
    - threat_score > 80
  params:
    channels: [pagerduty]
```

## Approval Workflows

Steps requiring human approval:

```yaml
- name: Terminate production instance
  type: cloud
  action: terminate_instance
  target: ${instance_id}
  approval_required: true
  approval_timeout: 3600    # Wait 1 hour for approval
  params:
    provider: aws
```

## Variable Substitution

Playbooks support variable interpolation:

```yaml
variables:
  host_ip: "192.168.1.100"
  incident_id: "INC-2024-001"

steps:
  - name: Scan ${host_ip}
    type: verification
    action: rescan
    target: ${host_ip}
```

Variables can be:
- Defined in playbook
- Passed at runtime
- Extracted from events

## Rollback Support

Define rollback steps for safe recovery:

```yaml
steps:
  - name: Isolate host
    type: containment
    action: isolate_host
    target: ${host_id}

rollback:
  - name: Restore network access
    type: containment
    action: unisolate_host
    target: ${host_id}
```

## Error Handling

Control behavior on failure:

```yaml
- name: Try to kill process
  type: edr
  action: kill_process
  target: ${host_id}
  on_failure: continue      # Options: continue | rollback | abort
  params:
    process_id: ${pid}
```

## Example Playbooks

### 1. Malware Isolation Playbook

```yaml
name: isolate-malware-host
version: 1.0.0
description: Isolate host with detected malware
author: security-team
tags: [malware, containment, automated]

triggers:
  - event_type: malware_detected
    conditions:
      severity: [high, critical]

variables:
  host_id: ""
  host_ip: ""
  malware_hash: ""
  incident_id: ""

steps:
  - name: Create incident ticket
    type: ticketing
    action: create_ticket
    params:
      provider: jira
      project: SEC
      summary: "Malware detected on ${host_ip}"
      priority: high

  - name: Collect forensics
    type: edr
    action: collect_forensics
    target: ${host_id}
    params:
      artifacts: [memory_dump, process_list, file_hashes]

  - name: Isolate host via EDR
    type: edr
    action: isolate_host
    target: ${host_id}
    approval_required: false

  - name: Quarantine at network level
    type: containment
    action: quarantine
    target: ${mac_address}
    params:
      provider: cisco_ise

  - name: Notify security team
    type: notification
    action: send_alert
    params:
      channels: [slack, email]
      message: "Host ${host_ip} isolated due to malware detection"

  - name: Re-scan after remediation
    type: verification
    action: rescan
    target: ${host_ip}
    params:
      scanner: aegis
      mode: comprehensive

postconditions:
  - verify: host_isolated
    params:
      host_id: ${host_id}
      method: connectivity_test

rollback:
  - name: Restore network access
    type: edr
    action: unisolate_host
    target: ${host_id}

metadata:
  severity: high
  category: containment
  rbac_role: security_operator
  audit: true
```

### 2. Unknown Device Response

```yaml
name: unknown-device-response
version: 1.0.0
description: Respond to unknown device on network
author: network-team
tags: [network, unknown-device, passive-defense]

triggers:
  - event_type: unknown_device_detected

variables:
  mac_address: ""
  ip_address: ""
  switch_ip: ""
  switch_port: ""
  device_oui: ""

steps:
  - name: Verify device is truly unknown
    type: verification
    action: check_asset_inventory
    params:
      mac: ${mac_address}

  - name: Collect device info
    type: collection
    action: enrich_device
    params:
      geoip: true
      whois: true
      threat_intel: true

  - name: Quarantine device
    type: containment
    action: quarantine
    target: ${mac_address}
    approval_required: true
    approval_timeout: 1800
    params:
      provider: aruba_clearpass
      vlan_id: 999

  - name: Disable switch port
    type: containment
    action: disable_port
    target: ${switch_ip}
    params:
      port: ${switch_port}

  - name: Generate incident report
    type: reporting
    action: generate_pdf
    params:
      template: universal
      include_timeline: true
      sign: true

metadata:
  severity: medium
  category: containment
  rbac_role: network_operator
  audit: true
```

### 3. Cloud Compromise Response

```yaml
name: cloud-instance-compromise
version: 1.0.0
description: Respond to compromised cloud instance
author: cloud-team
tags: [cloud, aws, compromise, forensics]

variables:
  instance_id: ""
  region: "us-east-1"
  account_id: ""

steps:
  - name: Snapshot all volumes
    type: cloud
    action: snapshot_volume
    target: ${instance_id}
    params:
      provider: aws
      region: ${region}
      description: "Forensic snapshot - incident ${incident_id}"

  - name: Isolate instance
    type: cloud
    action: isolate_instance
    target: ${instance_id}
    params:
      provider: aws
      region: ${region}
      security_group: sg-forensics

  - name: Collect instance metadata
    type: cloud
    action: collect_metadata
    target: ${instance_id}
    params:
      include: [tags, iam_role, security_groups, network_interfaces]

  - name: Terminate instance
    type: cloud
    action: terminate_instance
    target: ${instance_id}
    approval_required: true
    params:
      provider: aws
      region: ${region}

  - name: Rotate credentials
    type: cloud
    action: rotate_credentials
    params:
      account_id: ${account_id}
      scope: [api_keys, passwords]

  - name: Create incident report
    type: ticketing
    action: create_ticket
    params:
      provider: servicenow
      category: security_incident
      priority: high

metadata:
  severity: critical
  category: forensics
  rbac_role: cloud_admin
  audit: true
```

## Playbook Testing

Test playbooks in dry-run mode:

```bash
revenant run-playbook --id=pb-isolate-001 \
  --target=host-123 \
  --dry-run \
  --variables='{"host_ip":"192.168.1.100"}'
```

## Best Practices

1. **Always include rollback steps** for containment actions
2. **Use approval gates** for destructive actions
3. **Collect forensics before remediation**
4. **Include verification steps** after remediation
5. **Set appropriate timeouts** for all steps
6. **Tag playbooks** for easy discovery
7. **Version playbooks** semantically
8. **Test in dry-run mode** before production use
9. **Document all variables** and their purposes
10. **Use consistent naming conventions**

## Playbook Signing

For production, sign playbooks to prevent tampering:

```bash
revenant sign-playbook --file=playbook.yaml --key=signing-key.pem
```

Only signed playbooks will execute in production mode.
