from pathlib import Path
from typing import List
from .models import Event


def parse_log_file(path: str) -> List[Event]:
    events: List[Event] = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        timestamp = parts[0]
        kv = {}
        for item in parts[1:]:
            if '=' in item:
                k, v = item.split('=', 1)
                kv[k] = v
        events.append(Event(
            timestamp=timestamp,
            host=kv.get('host', 'unknown'),
            user=kv.get('user', 'unknown'),
            ip=kv.get('ip', '0.0.0.0'),
            action=kv.get('action', 'unknown'),
            source=kv.get('source', 'unknown')
        ))
    return events
