# Contributing - Phase 2 Development

Hey! If you're building Phase 2, this guide explains how Phase 1 works and what data it gives you.

## What Phase 2 needs to do

The goal is to take Phase 1's analysis and actually respond to incidents automatically:
1. Take the JSON output from Phase 1
2. Pick the right response playbook based on what type of incident it is
3. Run automated fixes for incidents we're confident about
4. Hand off tricky cases to humans

## What Phase 1 gives you

Here's the JSON structure you'll get from Phase 1:

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

## How to handle different confidence levels

### High confidence (0.7 and up)
Just do it automatically - block IPs, apply patches, whatever the playbook says. Tell the team afterwards.

### Medium confidence (0.6 to 0.69) 
Ask someone first, but have everything ready to go. Like "Should I quarantine this file?" with a one-click approve.

### Low confidence (under 0.6)
Don't touch anything automatically. Just collect evidence and hand it to a human analyst.

## How to structure Phase 2

### Main orchestrator
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

### Response modules
- **Network stuff**: Firewall rules, block IPs, DNS sinkholing
- **Endpoint actions**: Kill processes, quarantine files, fix registry  
- **App security**: WAF rules, lock accounts, kill sessions
- **Evidence**: Grab memory dumps, packet captures, logs

### Integration points
- **SIEM tools**: Splunk, ELK, QRadar - whatever you use
- **SOAR platforms**: Phantom, Demisto, XSOAR connections  
- **Tickets**: Auto-create Jira/ServiceNow tickets
- **Notifications**: Slack, Teams, email alerts

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