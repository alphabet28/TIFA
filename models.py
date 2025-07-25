"""
Data models for threat intelligence items
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json

@dataclass
class ThreatIntelItem:
    """Data structure for threat intelligence items"""
    id: str
    title: str
    description: str
    source: str
    published: str
    link: str
    iocs: Dict[str, List[str]]
    summary: str = ""
    severity: str = "unknown"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'source': self.source,
            'published': self.published,
            'link': self.link,
            'iocs': self.iocs,
            'summary': self.summary,
            'severity': self.severity,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ThreatIntelItem':
        """Create from dictionary"""
        return cls(
            id=data.get('id', ''),
            title=data.get('title', ''),
            description=data.get('description', ''),
            source=data.get('source', ''),
            published=data.get('published', ''),
            link=data.get('link', ''),
            iocs=data.get('iocs', {}),
            summary=data.get('summary', ''),
            severity=data.get('severity', 'unknown'),
            tags=data.get('tags', [])
        )
