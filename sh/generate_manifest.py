import json
import subprocess
import os
from datetime import datetime

def get_git_revision():
    try:
        return subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()
    except:
        return "unknown"

def main():
    manifest = {
        "timestamp": datetime.utcnow().isoformat(),
        "revision": get_git_revision(),
        "services": {
            "scanner-engine": {
                "language": "go",
                "path": "services/scanner-engine",
                "binary": "bin/overwatch"
            },
            "findings-ranker": {
                "language": "rust",
                "path": "services/findings-ranker",
                "binary": "bin/findings-ranker"
            },
            "poc-sandbox": {
                "language": "rust",
                "path": "services/poc-sandbox",
                "binary": "bin/poc-sandbox"
            }
        }
    }
    
    with open('build_manifest.json', 'w') as f:
        json.dump(manifest, f, indent=2)
    print("✓ build_manifest.json generated")

if __name__ == "__main__":
    main()
