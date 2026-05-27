from pathlib import Path
import json

def load_rules(path: str):
    return json.loads(Path(path).read_text(encoding='utf-8'))
