import yaml
from actions.docker_action_executor import isolate_host, patch_service, restart_service

ACTION_MAP = {
    "isolate-compromised-build-or-host": isolate_host,
    "restart-affected-services": restart_service,
    "patch-misconfigured-components": patch_service,
    "patch-authorization-logic": patch_service,
}

def run_playbook(path: str):
    with open(path, "r", encoding="utf-8") as f:
        pb = yaml.safe_load(f)

    print(f"Running playbook: {pb['playbook_id']} - {pb['description']}")
    for node in pb["nodes"]:
        node_id = node["id"]
        phase = node["phase"]
        print(f"\n[PHASE: {phase}] node: {node_id} – {node['description']}")

        # logic ง่ายๆ: ถ้ามีใน ACTION_MAP -> เรียกอัตโนมัติ
        if node_id in ACTION_MAP:
            print(f" -> auto action mapped, executing...")
            ACTION_MAP[node_id]()
        else:
            print(f" -> (no automation) this is documentation/manual step")

if __name__ == "__main__":
    run_playbook("playbooks/A05_injection.yaml")
