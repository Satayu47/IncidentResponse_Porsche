# Contributing to Incident Response ChatOps Bot

Welcome Phase-2 developers! 🚀 This guide will help you understand the Phase-1 output and build the automated response system.

## 🎯 Phase-2 Development Goals

Phase-2 should implement **automated dynamic playbooks** that:
1. **Process Phase-1 JSON output** 
2. **Select appropriate response playbooks** based on incident classification
3. **Execute automated countermeasures** for high-confidence incidents
4. **Escalate to humans** for complex cases requiring judgment

## 📥 Phase-1 Output Format

Phase-1 provides structured JSON with all necessary context:

```json
{
  "incident_type": "Web Application Attack",      // High-level category
  "fine_label": "xss",                          // Specific threat type  
  "confidence": 0.85,                           // AI confidence score
  "rationale": "Detected script injection patterns in user input",
  "entities": {
    "persons": ["admin", "user123"],            // People involved
    "orgs": ["webapp", "company.com"],          // Organizations/systems
    "cves": ["CVE-2023-1234"],                // Known vulnerabilities
    "cves_cwe": ["CWE-79"]                    // Weakness categories
  },
  "iocs": {
    "ip": ["192.168.1.100", "10.0.0.5"],     // IP addresses
    "url": ["http://evil.com/payload"],        // Malicious URLs
    "hash": ["a1b2c3d4e5f6..."]              // File hashes
  },
  "related_CVEs": ["CVE-2023-1234"],           // Vulnerability context
  "kb_excerpt": "CVE-2023-1234: XSS vulnerability in...",
  "timestamp_ms": 1698876543210               // Processing timestamp
}
```

## 🔄 Confidence-Based Workflow

### High Confidence (≥ 0.7)
- **Action**: Immediate automated response
- **Playbook**: Execute standard countermeasures
- **Notification**: Alert team post-execution
- **Example**: Block malicious IPs, patch known CVEs

### Medium Confidence (0.6-0.69) 
- **Action**: Execute with human approval
- **Playbook**: Prepare response, await confirmation
- **Notification**: Request operator review
- **Example**: Quarantine suspicious files, monitor traffic

### Low Confidence (< 0.6)
- **Action**: Manual investigation required  
- **Playbook**: Evidence collection only
- **Notification**: Escalate to security analyst
- **Example**: Log events, preserve forensics

## 🛠️ Suggested Phase-2 Architecture

### 1. Playbook Engine
```python
class PlaybookOrchestrator:
    def process_phase1_output(self, json_data):
        """Main entry point from Phase-1"""
        
    def select_playbook(self, incident_type, confidence):
        """Choose appropriate response playbook"""
        
    def execute_playbook(self, playbook, context):
        """Run automated countermeasures"""
        
    def escalate_to_human(self, reason, context):
        """Hand off to security analyst"""
```

### 2. Response Modules
- **Network**: Firewall rules, IP blocking, DNS sinkhole
- **Endpoint**: Process termination, file quarantine, registry cleanup  
- **Application**: WAF rules, account lockout, session invalidation
- **Forensics**: Evidence collection, memory dumps, network captures

### 3. Integration Points
- **SIEM**: Splunk, ELK, QRadar integration
- **SOAR**: Phantom, Demisto, XSOAR connectors  
- **Ticketing**: Jira, ServiceNow automation
- **Communication**: Slack, Teams, email notifications

## 📋 Development Roadmap

### Phase 2.1: Core Engine (Week 1-2)
- [ ] JSON input processor
- [ ] Basic playbook selector
- [ ] Confidence threshold logic
- [ ] Logging and audit trail

### Phase 2.2: Response Modules (Week 3-4)
- [ ] Network response actions
- [ ] Endpoint response actions  
- [ ] Application security responses
- [ ] Evidence preservation

### Phase 2.3: Integration (Week 5-6)
- [ ] SIEM connector
- [ ] SOAR platform integration
- [ ] Notification systems
- [ ] Dashboard/monitoring

### Phase 2.4: Advanced Features (Week 7-8)
- [ ] Machine learning feedback loop
- [ ] Custom playbook builder
- [ ] Multi-tenant support
- [ ] Advanced analytics

## 🧪 Testing Strategy

### Unit Tests
```python
def test_playbook_selection():
    """Test correct playbook chosen for incident type"""
    
def test_confidence_thresholds():
    """Verify automation vs human escalation logic"""
    
def test_response_execution():
    """Mock execution of countermeasures"""
```

### Integration Tests  
```python
def test_phase1_integration():
    """End-to-end workflow from Phase-1 JSON"""
    
def test_siem_integration():
    """SIEM platform connectivity"""
    
def test_rollback_capabilities():
    """Undo automated changes if needed"""
```

### Example Test Data
Use Phase-1 to generate realistic JSON outputs:
```bash
# Generate test cases
cd IncidentResponse_Phase1
streamlit run app.py

# Submit various incident types:
# - XSS: "Script injection in contact form"
# - SQLi: "Database errors in search function"  
# - Brute force: "Multiple failed login attempts"
# - RCE: "Command execution vulnerability"

# Download JSON outputs for Phase-2 testing
```

## 🔍 Key Integration Points

### 1. Input Validation
```python
def validate_phase1_output(json_data):
    """Ensure JSON has required fields and valid confidence"""
    required = ['incident_type', 'fine_label', 'confidence']
    assert all(field in json_data for field in required)
    assert 0.0 <= json_data['confidence'] <= 1.0
```

### 2. Playbook Mapping
```python
PLAYBOOK_MAP = {
    'xss': ['waf_rule_update', 'input_sanitization'],
    'sql_injection': ['database_lockdown', 'query_monitoring'],  
    'bruteforce': ['account_lockout', 'ip_blocking'],
    'rce': ['process_isolation', 'patch_deployment']
}
```

### 3. Execution Context
```python
class ExecutionContext:
    def __init__(self, phase1_data):
        self.incident_id = generate_id()
        self.classification = phase1_data['fine_label']
        self.confidence = phase1_data['confidence']
        self.targets = phase1_data['iocs']
        self.timeline = []  # Track all actions
```

## 📞 Getting Help

### Phase-1 Team Contact
- **Questions about JSON format**: Check `app.py` Phase-2 handoff section
- **Entity extraction details**: See `extractor.py` for IOC patterns
- **CVE context format**: Review `nvd.py` and `lc_retriever.py`

### Development Environment
```bash
# Setup Phase-1 for testing
git clone <repository>
pip install -r requirements.txt
python -m spacy download en_core_web_md

# Create .env with your keys
cp .env.example .env

# Run and test Phase-1 output
streamlit run app.py
```

### Debugging Tips
- **Enable debug logging** in Phase-1 to see full processing
- **Use download JSON feature** to get clean test data
- **Test various confidence levels** by submitting different incident types
- **Check CVE context** for vulnerability-specific responses

## 🎯 Success Metrics

Phase-2 should achieve:
- **< 30 second response time** for high-confidence incidents
- **> 95% uptime** for critical security responses  
- **Zero false positive** automated blocking (use confidence thresholds)
- **100% audit trail** for all automated actions
- **< 5 minute** escalation time for human review cases

---

**Ready to build the future of automated incident response!** 🛡️

The Phase-1 foundation is solid - now let's add the automation layer that makes security operations truly responsive and efficient.