"""
Database operations for threat intelligence storage and retrieval
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Optional
import logging
from models import ThreatIntelItem
from config import Config

logger = logging.getLogger(__name__)

class ThreatIntelDatabase:
    """SQLite database for storing threat intelligence data"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or Config.DATABASE_PATH
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                source TEXT,
                published TEXT,
                link TEXT,
                iocs TEXT,
                summary TEXT,
                severity TEXT,
                tags TEXT,
                created_at TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feed_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                url TEXT,
                feed_type TEXT,
                last_updated TEXT,
                active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_threat_intel_source 
            ON threat_intel(source)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_threat_intel_severity 
            ON threat_intel(severity)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_threat_intel_created_at 
            ON threat_intel(created_at)
        ''')
        
        conn.commit()
        conn.close()
    
    def save_threat_intel(self, item: ThreatIntelItem):
        """Save threat intelligence item to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO threat_intel 
                (id, title, description, source, published, link, iocs, summary, severity, tags, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item.id,
                item.title,
                item.description,
                item.source,
                item.published,
                item.link,
                json.dumps(item.iocs),
                item.summary,
                item.severity,
                json.dumps(item.tags),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            logger.debug(f"Saved threat intel item: {item.id}")
            
        except Exception as e:
            logger.error(f"Error saving threat intel item {item.id}: {str(e)}")
            
        finally:
            conn.close()
    
    def get_recent_threats(self, limit: int = None) -> List[ThreatIntelItem]:
        """Get recent threat intelligence items"""
        limit = limit or Config.MAX_RECENT_THREATS
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT * FROM threat_intel 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            return self._rows_to_items(rows)
            
        except Exception as e:
            logger.error(f"Error getting recent threats: {str(e)}")
            return []
            
        finally:
            conn.close()
    
    def search_threats(self, query: str, limit: int = None) -> List[ThreatIntelItem]:
        """Search threats by query"""
        limit = limit or Config.MAX_SEARCH_RESULTS
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT * FROM threat_intel 
                WHERE title LIKE ? OR description LIKE ? OR summary LIKE ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (f'%{query}%', f'%{query}%', f'%{query}%', limit))
            
            rows = cursor.fetchall()
            return self._rows_to_items(rows)
            
        except Exception as e:
            logger.error(f"Error searching threats: {str(e)}")
            return []
            
        finally:
            conn.close()
    
    def get_threats_by_severity(self, severity: str, limit: int = None) -> List[ThreatIntelItem]:
        """Get threats by severity level"""
        limit = limit or Config.MAX_RECENT_THREATS
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT * FROM threat_intel 
                WHERE severity = ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (severity, limit))
            
            rows = cursor.fetchall()
            return self._rows_to_items(rows)
            
        except Exception as e:
            logger.error(f"Error getting threats by severity {severity}: {str(e)}")
            return []
            
        finally:
            conn.close()
    
    def get_threats_by_source(self, source: str, limit: int = None) -> List[ThreatIntelItem]:
        """Get threats by source"""
        limit = limit or Config.MAX_RECENT_THREATS
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT * FROM threat_intel 
                WHERE source = ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (source, limit))
            
            rows = cursor.fetchall()
            return self._rows_to_items(rows)
            
        except Exception as e:
            logger.error(f"Error getting threats by source {source}: {str(e)}")
            return []
            
        finally:
            conn.close()
    
    def _rows_to_items(self, rows: List[tuple]) -> List[ThreatIntelItem]:
        """Convert database rows to ThreatIntelItem objects"""
        items = []
        for row in rows:
            try:
                item = ThreatIntelItem(
                    id=row[0],
                    title=row[1] or "",
                    description=row[2] or "",
                    source=row[3] or "",
                    published=row[4] or "",
                    link=row[5] or "",
                    iocs=json.loads(row[6]) if row[6] else {},
                    summary=row[7] or "",
                    severity=row[8] or "unknown",
                    tags=json.loads(row[9]) if row[9] else []
                )
                items.append(item)
            except Exception as e:
                logger.error(f"Error converting row to ThreatIntelItem: {str(e)}")
                continue
        
        return items
    
    def get_statistics(self) -> dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Total threats
            cursor.execute("SELECT COUNT(*) FROM threat_intel")
            total = cursor.fetchone()[0]
            
            # By severity
            cursor.execute("""
                SELECT severity, COUNT(*) 
                FROM threat_intel 
                GROUP BY severity
            """)
            severity_counts = dict(cursor.fetchall())
            
            # By source
            cursor.execute("""
                SELECT source, COUNT(*) 
                FROM threat_intel 
                GROUP BY source 
                ORDER BY COUNT(*) DESC
            """)
            source_counts = dict(cursor.fetchall())
            
            return {
                'total_threats': total,
                'severity_counts': severity_counts,
                'source_counts': source_counts
            }
            
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {
                'total_threats': 0,
                'severity_counts': {},
                'source_counts': {}
            }
            
        finally:
            conn.close()
