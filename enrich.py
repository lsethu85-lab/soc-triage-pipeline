from pathlib import Path
import json

def load_ioc_feed(path: str):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def enrich_ip(ip: str, ioc_feed):
    return ioc_feed.get(ip, {'reputation': 'unknown', 'confidence': 0, 'source': 'none'})
