from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any

@dataclass
class Event:
    timestamp: str
    host: str
    user: str
    ip: str
    action: str
    source: str = 'unknown'

@dataclass
class Alert:
    alert_id: str
    title: str
    rule_name: str
    user: str
    source_ip: str
    host: str
    count: int
    score: int
    severity: str
    mitre: List[str]
    ioc_enrichment: Dict[str, Any]
    correlation_notes: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
