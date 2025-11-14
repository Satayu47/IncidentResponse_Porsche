import subprocess
import datetime
from pathlib import Path

# Log file in project root
LOG_FILE = Path("sandbox_actions.log")


def log(msg: str):
    """Log to console and sandbox_actions.log"""
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    line = f"[{ts}] {msg}"
    print(line)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def run(cmd: str):
    """Run a shell command and log it."""
    log(f"$ {cmd}")
    subprocess.run(cmd, shell=True, check=False)


def isolate_host(container: str = "victim_host", network: str = "docker-sandbox_ir-net"):
    """
    Disconnect container from Docker network (containment / isolate host).
    Make sure 'network' matches `docker network ls`.
    """
    run(f"docker network disconnect {network} {container}")
    log(f"HOST_ISOLATED container={container} network={network}")


def reconnect_host(container: str = "victim_host", network: str = "docker-sandbox_ir-net"):
    """Reconnect container to Docker network (for testing / recovery)."""
    run(f"docker network connect {network} {container}")
    log(f"HOST_RECONNECTED container={container} network={network}")


def patch_service(container: str = "victim_host"):
    """Simulate patching by upgrading nginx inside container."""
    run(
        f'docker exec {container} bash -c '
        '"apt-get update && apt-get install --only-upgrade -y nginx"'
    )
    log(f"SERVICE_PATCHED container={container} service=nginx")


def restart_service(container: str = "victim_host"):
    """Restart nginx inside container (recovery)."""
    run(f"docker exec {container} service nginx restart")
    log(f"SERVICE_RESTARTED container={container} service=nginx")
