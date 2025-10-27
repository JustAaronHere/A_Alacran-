# PDF Incident Report Template Specification

## Overview

The Gatehound module generates universal, forensic-grade PDF incident reports for all detected security events. These reports are designed to be court-admissible, tamper-evident, and comprehensive.

## Report Structure

### 1. Cover Page

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              SECURITY INCIDENT REPORT                     ║
║                                                           ║
║                   [COMPANY LOGO]                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

Incident ID:    INC-2024-10-26-001
Classification: CONFIDENTIAL
Generated:      2024-10-26 15:30:00 UTC
Report Version: 1.0
Status:         [OPEN | CLOSED | UNDER INVESTIGATION]

Prepared by:    Aegis Sentinel Suite - Gatehound Module
Contact:        security@example.com
```

### 2. Executive Summary (Page 2)

```
EXECUTIVE SUMMARY
─────────────────────────────────────────────────────────

Incident Type:      Unknown Device Detected
Severity:           HIGH
Detection Time:     2024-10-26 14:15:32 UTC
Response Time:      2024-10-26 14:16:45 UTC (73 seconds)
Current Status:     Contained and Under Investigation

Summary:
An unknown device with MAC address 00:1A:2B:3C:4D:5E was detected
on the corporate network at 192.168.1.105. The device was not found
in the asset inventory and exhibited suspicious behavior. Automated
containment was triggered, quarantining the device to VLAN 999.

Impact Assessment:
- Network: Isolated, no lateral movement detected
- Data: No exfiltration detected
- Systems: No compromise detected

Recommended Actions:
1. Investigate device owner and purpose
2. Review network logs for anomalies
3. Update asset inventory if legitimate
4. Maintain quarantine until verification complete
```

### 3. Incident Timeline (Page 3)

```
INCIDENT TIMELINE
─────────────────────────────────────────────────────────

[Timeline visualization with events]

14:15:32 UTC │ DETECTION    │ Unknown device detected via ARP
             │              │ MAC: 00:1A:2B:3C:4D:5E
             │              │ IP: 192.168.1.105
             │              │
14:15:35 UTC │ ENRICHMENT   │ GeoIP lookup completed
             │              │ ASN: AS15169 (Google LLC)
             │              │ Location: Mountain View, CA
             │              │
14:15:38 UTC │ CORRELATION  │ Device not in asset inventory
             │              │ Threat score: 65/100
             │              │
14:16:02 UTC │ ALERT        │ Security team notified
             │              │ Channels: Slack, Email
             │              │
14:16:45 UTC │ CONTAINMENT  │ Device quarantined via Cisco ISE
             │              │ VLAN: 999 (Quarantine)
             │              │
14:17:10 UTC │ FORENSICS    │ PCAP captured and encrypted
             │              │ Size: 2.3 MB
             │              │ SHA256: a1b2c3d4...
             │              │
14:18:00 UTC │ REPORT       │ Incident report generated
             │              │ Status: Under Investigation
```

### 4. Device Profile (Page 4)

```
DEVICE PROFILE
─────────────────────────────────────────────────────────

Network Information
  MAC Address:      00:1A:2B:3C:4D:5E
  IP Address:       192.168.1.105
  Hostname:         Unknown
  OUI Vendor:       Apple, Inc.
  First Seen:       2024-10-26 14:15:32 UTC
  Last Seen:        2024-10-26 14:16:40 UTC

DHCP Fingerprint
  Client ID:        01:00:1a:2b:3c:4d:5e
  Hostname:         Johns-MacBook
  Vendor Class:     MSFT 5.0
  Requested Options: 1,3,6,15,119,252

HTTP/TLS Fingerprint
  User-Agent:       Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
  TLS Version:      TLSv1.3
  Cipher Suites:    TLS_AES_128_GCM_SHA256, ...
  SNI:              api.example.com

Operating System Detection
  OS Guess:         macOS 10.15+ (Catalina or newer)
  TTL:              64
  TCP Window:       65535
  Confidence:       High (95%)

Behavior Analysis
  ARP Requests:     12
  DNS Queries:      45 (domains: api.example.com, google.com, ...)
  HTTP Requests:    8
  TLS Connections:  15
  Unusual Activity: None detected
```

### 5. Network Context (Page 5)

```
NETWORK CONTEXT
─────────────────────────────────────────────────────────

Router/Gateway Information
  Gateway IP:       192.168.1.1
  Gateway MAC:      AA:BB:CC:DD:EE:FF
  Router Model:     Cisco ISR 4331
  Switch Port:      GigabitEthernet1/0/24
  Switch IP:        192.168.1.250
  VLAN:             10 (Corporate LAN)

Geolocation & Ownership
  IP Address:       203.0.113.45 (Public)
  ASN:              AS15169
  Organization:     Google LLC
  Country:          United States
  Region:           California
  City:             Mountain View
  Coordinates:      37.4056, -122.0775
  ISP:              Google Fiber

[Embedded map showing approximate location]

WHOIS Information
  Registrar:        ARIN
  Updated:          2024-01-15
  Abuse Contact:    abuse@google.com
  CIDR:             203.0.113.0/24
```

### 6. Threat Intelligence (Page 6)

```
THREAT INTELLIGENCE & CORRELATION
─────────────────────────────────────────────────────────

Threat Score: 65/100 (MEDIUM-HIGH)

Scoring Breakdown
  Unknown Device:           +30 points
  Not in Asset Inventory:   +20 points
  Suspicious User-Agent:    +15 points
  No Historical Sighting:   +10 points
  Clean IP Reputation:      -10 points

Blacklist Checks
  ✓ IP not found in AbuseIPDB
  ✓ IP not found in Spamhaus
  ✓ MAC not in internal blocklist
  ✓ No match in STIX/TAXII feeds

Similar Incidents
  • INC-2024-09-12-034: Unknown MacBook on guest network
  • INC-2024-08-05-021: Unauthorized BYOD device

Indicators of Compromise (IoCs)
  MAC:  00:1A:2B:3C:4D:5E (Flagged)
  IP:   192.168.1.105 (Monitoring)
  Host: Johns-MacBook (Suspicious hostname)

MITRE ATT&CK Mapping
  Tactic:     Initial Access (TA0001)
  Technique:  Valid Accounts (T1078)
  Sub-Tech:   Default Accounts (T1078.001)
```

### 7. Network Evidence (Page 7)

```
NETWORK EVIDENCE
─────────────────────────────────────────────────────────

Packet Capture
  File:         evidence-inc-2024-10-26-001.pcap (encrypted)
  Size:         2.34 MB (2,456,789 bytes)
  Packets:      3,421
  Duration:     68 seconds
  SHA256:       a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
  Encryption:   AES-256-GCM
  Key ID:       key-2024-10-26
  Location:     /evidence/2024/10/26/inc-001.pcap.enc

Protocol Distribution
  TCP:          65% (2,223 packets)
  UDP:          25% (855 packets)
  ICMP:         5% (171 packets)
  ARP:          3% (103 packets)
  Other:        2% (69 packets)

Top Conversations
  192.168.1.105:52341 ↔ 203.0.113.20:443   (TLS)  1.2 MB
  192.168.1.105:51823 ↔ 8.8.8.8:53         (DNS)  45 KB
  192.168.1.105:52342 ↔ 192.168.1.50:445   (SMB)  340 KB

DNS Queries (Sample)
  • api.example.com         → 203.0.113.20
  • cdn.jsdelivr.net        → 151.101.1.229
  • www.google.com          → 142.250.185.36
```

### 8. Response Actions (Page 8)

```
RESPONSE ACTIONS TAKEN
─────────────────────────────────────────────────────────

Automated Actions
  ✓ Device quarantined to VLAN 999
  ✓ Switch port GigabitEthernet1/0/24 monitoring enabled
  ✓ Traffic logging activated
  ✓ Security team notified
  ✓ Forensic evidence collected
  ✓ Chain-of-custody established

Manual Actions Required
  ⧖ Investigate device owner/purpose
  ⧖ Interview user "John" (if employee)
  ⧖ Review physical security logs
  ⧖ Determine if device is authorized BYOD
  ⧖ Update asset inventory if legitimate

Containment Status
  Network Access:     RESTRICTED (Quarantine VLAN only)
  Internet Access:    DENIED
  Internal Resources: DENIED
  Monitoring:         ACTIVE

Evidence Chain-of-Custody
  1. Captured by:     Gatehound v1.0.0 on sensor-01
  2. Encrypted:       2024-10-26 14:17:10 UTC
  3. Stored:          /evidence/2024/10/26/inc-001/
  4. Hash Verified:   2024-10-26 14:17:15 UTC
  5. Signed:          2024-10-26 14:18:00 UTC
  6. Custodian:       SOC-Team-Lead
```

### 9. Recommended Remediation (Page 9)

```
RECOMMENDED REMEDIATION STEPS
─────────────────────────────────────────────────────────

Immediate Actions (0-4 hours)
  1. Verify device owner and purpose
     - Contact potential owner (John)
     - Check HR records for employee status
     - Review guest access requests

  2. Assess risk level
     - Determine if device accessed sensitive data
     - Review network logs for lateral movement
     - Check for data exfiltration attempts

  3. Make containment decision
     - If legitimate: Update asset inventory, release from quarantine
     - If unauthorized: Maintain isolation, escalate to management
     - If malicious: Involve law enforcement, preserve evidence

Short-Term Actions (4-24 hours)
  4. Update security policies
     - Review BYOD policy if applicable
     - Strengthen NAC rules
     - Update asset management procedures

  5. Enhance monitoring
     - Increase logging on affected VLAN
     - Deploy additional sensors if needed
     - Review similar recent events

Long-Term Actions (1-7 days)
  6. Security awareness training
     - Educate staff on BYOD policy
     - Reinforce reporting procedures
     - Share incident learnings (anonymized)

  7. Process improvements
     - Review onboarding procedures
     - Enhance asset tracking
     - Implement continuous monitoring

  8. Technology enhancements
     - Consider 802.1X for stronger access control
     - Evaluate endpoint detection solutions
     - Improve network segmentation
```

### 10. Appendices (Pages 10+)

```
APPENDIX A: RAW EVENT DATA (JSON)
─────────────────────────────────────────────────────────

{
  "event_id": "evt-2024-10-26-001",
  "type": "unknown_device_detected",
  "timestamp": "2024-10-26T14:15:32Z",
  "severity": "high",
  "device": {
    "mac_address": "00:1A:2B:3C:4D:5E",
    "ip_address": "192.168.1.105",
    "hostname": "Johns-MacBook",
    "oui_vendor": "Apple, Inc."
  },
  "network": {
    "gateway": "192.168.1.1",
    "switch_ip": "192.168.1.250",
    "switch_port": "GigabitEthernet1/0/24",
    "vlan": 10
  },
  ...
}

APPENDIX B: CONFIGURATION SNAPSHOT
─────────────────────────────────────────────────────────

[Network configuration at time of incident]
[NAC policy configuration]
[Monitoring sensor configuration]

APPENDIX C: EVIDENCE MANIFEST
─────────────────────────────────────────────────────────

Evidence Item 1: Packet Capture
  File:     evidence-inc-2024-10-26-001.pcap.enc
  Hash:     a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...
  Size:     2,456,789 bytes
  Created:  2024-10-26 14:17:10 UTC
  Signed:   Yes
  
Evidence Item 2: System Logs
  File:     logs-inc-2024-10-26-001.json.enc
  Hash:     b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7...
  Size:     145,678 bytes
  Created:  2024-10-26 14:17:20 UTC
  Signed:   Yes
```

### 11. Signature Page (Final Page)

```
DIGITAL SIGNATURE & VERIFICATION
─────────────────────────────────────────────────────────

This report has been digitally signed to ensure integrity
and authenticity. Any tampering will invalidate the signature.

Report Hash (SHA-256):
  f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2

Digital Signature (ed25519):
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
  [Full signature here]

Signed By:
  System:       Gatehound v1.0.0
  Operator:     SOC-Analyst-01
  Timestamp:    2024-10-26 14:18:00 UTC
  Key ID:       signing-key-2024

Verification:
  To verify this report's authenticity:
  
  1. Calculate SHA-256 hash of report content (excluding this page)
  2. Verify signature using public key:
     curl https://sentinel.example.com/keys/signing-key-2024.pub
  3. Use verification tool:
     gatehound verify-report --file=report.pdf --key=signing-key-2024.pub

─────────────────────────────────────────────────────────

CONFIDENTIAL - DO NOT DISTRIBUTE WITHOUT AUTHORIZATION

Generated by: Aegis Sentinel Suite - Gatehound Module
Version:      1.0.0
Contact:      security@example.com
Page:         11 of 11
```

## Styling Guidelines

### Colors
- **Header/Footer**: Dark blue (#1a3a5c)
- **Section Titles**: Medium blue (#3366cc)
- **Warning Text**: Orange (#ff9900)
- **Critical Text**: Red (#cc0000)
- **Success Text**: Green (#009900)
- **Body Text**: Black (#000000)

### Fonts
- **Headers**: Helvetica Bold, 18pt
- **Subheaders**: Helvetica Bold, 14pt
- **Body Text**: Helvetica, 11pt
- **Code/Data**: Courier, 10pt
- **Footer**: Helvetica, 8pt

### Layout
- **Page Size**: A4 (210mm x 297mm)
- **Margins**: Top 25mm, Bottom 25mm, Left 20mm, Right 20mm
- **Line Spacing**: 1.15
- **Header Height**: 20mm
- **Footer Height**: 15mm

### Watermark
Optional "CONFIDENTIAL" diagonal watermark in light gray on each page.

## Generation Notes

1. **Always include page numbers** in footer
2. **Timestamp in footer**: "Generated: YYYY-MM-DD HH:MM:SS UTC"
3. **Incident ID in header**: Consistent across all pages
4. **Classification marking**: On every page (CONFIDENTIAL, etc.)
5. **Embed signature data**: Final page must include cryptographic signature
6. **Accessibility**: Ensure PDF is screen-reader compatible
7. **Print-friendly**: Use appropriate colors and contrast

## File Naming Convention

```
incident-report-{INCIDENT_ID}-{TIMESTAMP}.pdf

Example:
incident-report-INC-2024-10-26-001-20241026141800.pdf
```

## Metadata

PDF metadata should include:
- Title: "Security Incident Report - {INCIDENT_ID}"
- Author: "Aegis Sentinel Suite - Gatehound"
- Subject: "Incident Type - Severity"
- Keywords: "security, incident, forensics"
- Creator: "Gatehound v{VERSION}"
- Creation Date: ISO8601 timestamp

## Security Features

1. **Password Protection**: Optional password for opening
2. **Encryption**: AES-256 encryption
3. **Permissions**: Restrict printing/editing
4. **Digital Signature**: Embedded cryptographic signature
5. **Tamper Detection**: Hash verification

## Compliance Considerations

Reports are designed to meet requirements for:
- **ISO 27001**: Information security management
- **NIST CSF**: Cybersecurity Framework
- **SOC 2**: Security and availability
- **GDPR**: Data protection (redact PII as needed)
- **HIPAA**: Healthcare data protection (if applicable)
- **PCI DSS**: Payment card industry standards
