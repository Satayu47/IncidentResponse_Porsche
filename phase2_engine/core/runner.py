"""
Phase 2 Runner - Connects Phase 1 classification to automated response playbooks
"""
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class Phase2Runner:
    """Executes automated response playbooks based on Phase 1 incident classification"""
    
    def __init__(self, playbook_dir: str = None):
        if playbook_dir is None:
            # Default to playbooks folder next to this file
            self.playbook_dir = Path(__file__).parent.parent / "playbooks"
        else:
            self.playbook_dir = Path(playbook_dir)
    
    def map_incident_to_playbook(self, incident: Dict[str, Any]) -> Optional[str]:
        """
        Map Phase 1 incident type to appropriate OWASP playbook
        
        Args:
            incident: Phase 1 JSON output with incident_type and fine_label
            
        Returns:
            Path to playbook YAML file, or None if no match
        """
        incident_type = incident.get("incident_type", "")
        fine_label = incident.get("fine_label", "")
        
        # Map Phase 1 labels to Phase 2 playbook files
        playbook_mapping = {
            # Incident type mappings
            "Injection Attack": "A05_injection.yaml",
            "Denial of Service": "A07_authentication_failures.yaml",
            "Broken Access Control": "A01_broken_access_control.yaml",
            "Cryptographic Failures": "A04_cryptographic_failures.yaml",
            "Misconfiguration": "A02_security_misconfiguration.yaml",
            "Vulnerable Components": "A03_supply_chain.yaml",
            # Fine label mappings
            "injection": "A05_injection.yaml",
            "sql_injection": "A05_injection.yaml",
            "xss": "A05_injection.yaml",
            "broken_access_control": "A01_broken_access_control.yaml",
            "broken_authentication": "A07_authentication_failures.yaml",
            "sensitive_data_exposure": "A04_cryptographic_failures.yaml",
            "security_misconfiguration": "A02_security_misconfiguration.yaml",
            "misconfig": "A02_security_misconfiguration.yaml",
            "insecure_design": "A06_insecure_design.yaml",
            "supply_chain": "A03_supply_chain.yaml",
            "integrity_failures": "A08_integrity_failures.yaml",
            "logging_failure": "A09_logging_alerting.yaml",
            "vulnerable_component": "A03_supply_chain.yaml",
            "malware": "A05_injection.yaml",  # Treat as potential injection vector
        }
        
        # Try mapping by fine_label first (more specific)
        playbook_file = playbook_mapping.get(fine_label)
        
        # If not found, try incident_type (more general)
        if not playbook_file:
            playbook_file = playbook_mapping.get(incident_type)
        
        if playbook_file:
            playbook_path = self.playbook_dir / playbook_file
            if playbook_path.exists():
                return str(playbook_path)
        
        return None
    
    def load_playbook(self, playbook_path: str) -> Optional[Dict]:
        """Load YAML playbook file"""
        try:
            with open(playbook_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading playbook {playbook_path}: {e}")
            return None
    
    def execute_playbook(self, incident: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
        """
        Execute automated response based on incident classification
        
        Args:
            incident: Phase 1 JSON output
            dry_run: If True, simulate actions without executing (default)
            
        Returns:
            Dictionary with execution results
        """
        # Find appropriate playbook
        playbook_path = self.map_incident_to_playbook(incident)
        
        if not playbook_path:
            return {
                "status": "no_playbook",
                "message": f"No playbook found for incident type: {incident.get('incident_type')}",
                "incident": incident
            }
        
        # Load playbook
        playbook = self.load_playbook(playbook_path)
        
        if not playbook:
            return {
                "status": "load_error",
                "message": f"Failed to load playbook: {playbook_path}",
                "incident": incident
            }
        
        # Extract playbook info
        playbook_name = playbook.get("category", playbook.get("name", "Unknown"))
        description = playbook.get("description", "")
        nodes = playbook.get("nodes", [])  # YAML uses "nodes" not "steps"
        
        # Execute steps (simulated for dry_run)
        executed_steps = []
        for idx, node in enumerate(nodes, 1):
            step_name = node.get("description", f"Step {idx}")
            ui_desc = node.get("ui_description", "")
            action = node.get("type", "unknown")
            phase = node.get("phase", "unknown")
            
            if dry_run:
                executed_steps.append({
                    "step": idx,
                    "name": step_name,
                    "ui_description": ui_desc,
                    "action": action,
                    "phase": phase,
                    "status": "simulated",
                    "message": f"Would execute: {action}"
                })
            else:
                # TODO: Integrate with docker_action_executor for real execution
                executed_steps.append({
                    "step": idx,
                    "name": step_name,
                    "ui_description": ui_desc,
                    "action": action,
                    "phase": phase,
                    "status": "pending",
                    "message": "Real execution not yet implemented"
                })
        
        return {
            "status": "success",
            "playbook": playbook_name,
            "playbook_path": playbook_path,
            "description": description,
            "incident_type": incident.get("incident_type"),
            "confidence": incident.get("confidence"),
            "steps_executed": len(executed_steps),
            "steps": executed_steps,
            "dry_run": dry_run
        }


def run_phase2_from_incident(incident: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """
    Convenience function to run Phase 2 response
    
    Args:
        incident: Phase 1 JSON output
        dry_run: If True, simulate without executing
        
    Returns:
        Execution results
    """
    runner = Phase2Runner()
    return runner.execute_playbook(incident, dry_run=dry_run)


if __name__ == "__main__":
    # Test with sample incident
    sample_incident = {
        "incident_type": "Injection Attack",
        "fine_label": "injection",
        "confidence": 0.95,
        "rationale": "SQL injection detected",
        "iocs": {"ip": [], "url": []},
        "related_CVEs": []
    }
    
    result = run_phase2_from_incident(sample_incident)
    print(json.dumps(result, indent=2))
