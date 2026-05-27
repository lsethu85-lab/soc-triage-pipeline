from pathlib import Path
import json

def load_github_security_events(path: str):
    return json.loads(Path(path).read_text(encoding='utf-8'))
