#!/usr/bin/env python3
"""
Threat Intelligence Feed Aggregator
A simple, all-in-one script for collecting, analyzing, and viewing threat intelligence.
"""

import gradio as gr
import feedparser
import requests
from bs4 import BeautifulSoup
import sqlite3
import json
from datetime import datetime
import logging
import re
import os
from dotenv import load_dotenv
import google.generativeai as genai
from typing import List, Dict, Optional, Set, Any

# --- Configuration ---
class Config:
    """Configuration settings for the application"""
    load_dotenv()
    
    # Feed URLs
    THREAT_FEEDS = [
        {"name": "US-CERT CISA", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "category": "government"},
        {"name": "SANS Internet Storm Center", "url": "https://isc.sans.edu/rssfeed.xml", "category": "threat_intel"},
        {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "category": "blog"},
        {"name": "Malware Bytes Labs", "url": "https://blog.malwarebytes.com/feed/", "category": "blog"},
        {"name": "Threat Post", "url": "https://threatpost.com/feed/", "category": "news"},
    ]
    
    # Database
    DB_PATH = "threat_intel.db"
    
    # AI Analysis (Gemini)
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    GEMINI_MODEL = "gemini-1.5-flash"
    
    # Gradio Dashboard
    GRADIO_PORT = 7860
    GRADIO_SHARE = False

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Data Model ---
class ThreatIntelItem:
    """Represents a single threat intelligence item"""
    def __init__(self, title: str, link: str, summary: str, source: str, published_date: str, iocs: Dict[str, Set[str]], severity: str = "Medium"):
        self.id = f"{source}:{link}"
        self.title = title
        self.link = link
        self.summary = summary
        self.source = source
        self.published_date = published_date
        self.iocs = iocs
        self.severity = severity
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "link": self.link,
            "summary": self.summary,
            "source": self.source,
            "published_date": self.published_date,
            "iocs": {k: list(v) for k, v in self.iocs.items()},
            "severity": self.severity,
            "created_at": self.created_at
        }

# --- Database ---
class ThreatIntelDatabase:
    """Handles all database operations"""
    def __init__(self, db_path: str = Config.DB_PATH):
        self.db_path = db_path
        self.create_table()

    def create_table(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id TEXT PRIMARY KEY,
                title TEXT,
                link TEXT,
                summary TEXT,
                source TEXT,
                published_date TEXT,
                iocs TEXT,
                severity TEXT,
                created_at TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def item_exists(self, item_id: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM threat_intel WHERE id = ?", (item_id,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists

    def save_item(self, item: ThreatIntelItem):
        if self.item_exists(item.id):
            logger.info(f"Item already exists: {item.title}")
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO threat_intel (id, title, link, summary, source, published_date, iocs, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            item.id, item.title, item.link, item.summary, item.source,
            item.published_date, json.dumps({k: list(v) for k, v in item.iocs.items()}),
            item.severity, item.created_at
        ))
        conn.commit()
        conn.close()
        logger.info(f"Saved new threat: {item.title}")

    def get_recent_threats(self, limit: int = 20) -> List[ThreatIntelItem]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_intel ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_item(row) for row in rows]

    def search_ioc(self, ioc_query: str) -> List[ThreatIntelItem]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_intel WHERE iocs LIKE ?", (f'%{ioc_query}%',))
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_item(row) for row in rows]

    def get_statistics(self) -> Dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM threat_intel")
        total_threats = cursor.fetchone()[0]
        
        cursor.execute("SELECT iocs FROM threat_intel")
        all_iocs = [json.loads(row[0]) for row in cursor.fetchall() if row[0]]
        total_iocs_count = sum(len(ioc_list) for ioc_dict in all_iocs for ioc_list in ioc_dict.values())

        cursor.execute("SELECT COUNT(DISTINCT source) FROM threat_intel")
        total_sources = cursor.fetchone()[0]

        cursor.execute("SELECT MAX(created_at) FROM threat_intel")
        last_update_row = cursor.fetchone()
        last_update = last_update_row[0] if last_update_row and last_update_row[0] else "N/A"

        conn.close()
        return {
            "total_threats": total_threats,
            "total_iocs": total_iocs_count,
            "total_sources": total_sources,
            "last_update": last_update
        }

    def _row_to_item(self, row: tuple) -> ThreatIntelItem:
        iocs_dict = json.loads(row[6]) if row[6] else {}
        iocs_sets = {k: set(v) for k, v in iocs_dict.items()}
        item = ThreatIntelItem(
            title=row[1], link=row[2], summary=row[3], source=row[4],
            published_date=row[5], iocs=iocs_sets, severity=row[7]
        )
        item.id = row[0]
        item.created_at = row[8]
        return item

# --- IOC Extractor ---
class IOCExtractor:
    """Extracts Indicators of Compromise from text"""
    def extract(self, text: str) -> Dict[str, Set[str]]:
        iocs = {
            "ips": set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)),
            "domains": set(re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b', text)),
            "hashes": set(re.findall(r'\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b', text)),
            "urls": set(re.findall(r'https?://[^\s/$.?#].[^\s]*', text))
        }
        # Basic filtering
        iocs["domains"] -= {"cve.mitre.org"}
        return iocs

# --- AI Analyzer ---
class AIAnalyzer:
    """Analyzes threat content using AI"""
    def __init__(self):
        if Config.GOOGLE_API_KEY:
            genai.configure(api_key=Config.GOOGLE_API_KEY)
            self.model = genai.GenerativeModel(Config.GEMINI_MODEL)
            logger.info("✅ Gemini AI Analyzer initialized successfully")
        else:
            self.model = None
            logger.warning("⚠️ Gemini API key not found. AI features will be disabled.")

    def analyze(self, content: str) -> Dict[str, Any]:
        if not self.model:
            return {"summary": content[:500], "severity": "Medium"}

        prompt = f"""
        Analyze the following threat intelligence report. Provide a concise summary (max 100 words)
        and a severity rating (Low, Medium, High, Critical).
        
        Report: "{content}"
        
        Format your response as a JSON object with keys "summary" and "severity".
        """
        try:
            response = self.model.generate_content(prompt)
            result = json.loads(response.text)
            return result
        except Exception as e:
            logger.error(f"Error during AI analysis: {e}")
            return {"summary": content[:500], "severity": "Medium"}

# --- Feed Collector ---
class FeedCollector:
    """Collects and parses threat intelligence feeds"""
    def __init__(self, db: ThreatIntelDatabase, ioc_extractor: IOCExtractor):
        self.db = db
        self.ioc_extractor = ioc_extractor

    def fetch_feed(self, feed_info: Dict[str, str]) -> List[ThreatIntelItem]:
        logger.info(f"Fetching feed: {feed_info['name']}")
        items = []
        try:
            feed = feedparser.parse(feed_info["url"])
            for entry in feed.entries:
                title = entry.title
                link = entry.link
                summary = self._get_summary(entry)
                published = entry.get("published", datetime.now().isoformat())
                
                if self.db.item_exists(f"{feed_info['name']}:{link}"):
                    continue

                full_text = f"{title} {summary}"
                iocs = self.ioc_extractor.extract(full_text)
                
                item = ThreatIntelItem(
                    title=title, link=link, summary=summary,
                    source=feed_info["name"], published_date=published, iocs=iocs
                )
                items.append(item)
        except Exception as e:
            logger.error(f"Failed to fetch feed {feed_info['name']}: {e}")
        return items

    def _get_summary(self, entry) -> str:
        if 'summary' in entry:
            soup = BeautifulSoup(entry.summary, 'html.parser')
            return soup.get_text().strip()
        return "No summary available."

# --- Aggregator ---
class ThreatIntelAggregator:
    """Coordinates all components to collect and process threat intelligence"""
    def __init__(self):
        self.db = ThreatIntelDatabase()
        self.ioc_extractor = IOCExtractor()
        self.feed_collector = FeedCollector(self.db, self.ioc_extractor)
        self.ai_analyzer = AIAnalyzer()

    def run_aggregation(self):
        logger.info("Starting threat intelligence aggregation...")
        for feed_info in Config.THREAT_FEEDS:
            new_items = self.feed_collector.fetch_feed(feed_info)
            for item in new_items:
                analysis = self.ai_analyzer.analyze(item.summary)
                item.summary = analysis.get("summary", item.summary)
                item.severity = analysis.get("severity", "Medium")
                self.db.save_item(item)
        logger.info("Threat intelligence aggregation finished.")

# --- Dashboard ---
class SimpleThreatDashboard:
    """Simple, clean threat intelligence dashboard"""
    def __init__(self, aggregator: ThreatIntelAggregator):
        self.aggregator = aggregator

    def get_threat_summary(self) -> str:
        try:
            threats = self.aggregator.db.get_recent_threats(limit=10)
            if not threats:
                return "<div style='text-align: center;'><h3>🛡️ No threats found</h3><p>Click 'Refresh Feeds' to collect data.</p></div>"
            
            html = "<div>"
            for threat in threats:
                severity_color = {"High": "#ef4444", "Medium": "#f59e0b", "Low": "#10b981"}.get(threat.severity, "#6b7280")
                html += f"""
                <div style='border-left: 4px solid {severity_color}; padding: 10px; margin-bottom: 10px; background: #f9fafb;'>
                    <strong>{threat.title}</strong> <span style='background:{severity_color};color:white;padding:2px 6px;border-radius:10px;font-size:12px;'>{threat.severity}</span>
                    <p style='color:#6b7280;font-size:14px;'>Source: {threat.source} | Date: {threat.published_date}</p>
                    <p>{threat.summary[:200]}...</p>
                </div>
                """
            html += "</div>"
            return html
        except Exception as e:
            logger.error(f"Error getting threat summary: {e}")
            return f"<div style='color:red;'>Error: {e}</div>"

    def refresh_feeds(self):
        try:
            self.aggregator.run_aggregation()
            return self.get_threat_summary(), "<div style='color:green;'>✅ Feeds refreshed successfully!</div>"
        except Exception as e:
            logger.error(f"Error refreshing feeds: {e}")
            return self.get_threat_summary(), f"<div style='color:red;'>❌ Error: {e}</div>"

    def search_iocs(self, query: str) -> str:
        if not query.strip():
            return "<p>Enter an IOC to search.</p>"
        try:
            results = self.aggregator.db.search_ioc(query.strip())
            if not results:
                return f"<p>No matches found for '{query}'.</p>"
            
            html = f"<h4>Results for '{query}' ({len(results)} found):</h4>"
            for threat in results[:10]:
                html += f"<div style='padding:5px;border-bottom:1px solid #eee;'><strong>{threat.title}</strong> ({threat.source})</div>"
            return html
        except Exception as e:
            logger.error(f"Error searching IOCs: {e}")
            return f"<div style='color:red;'>Error: {e}</div>"

    def get_statistics(self) -> str:
        try:
            stats = self.aggregator.db.get_statistics()
            return f"""
            <div>
                <h3>📊 Statistics</h3>
                <p><strong>Total Threats:</strong> {stats['total_threats']}</p>
                <p><strong>Total IOCs:</strong> {stats['total_iocs']}</p>
                <p><strong>Sources:</strong> {stats['total_sources']}</p>
                <p><strong>Last Update:</strong> {stats['last_update']}</p>
            </div>
            """
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return f"<div style='color:red;'>Error: {e}</div>"

    def launch(self):
        with gr.Blocks(title="🛡️ Threat Intelligence Dashboard", theme=gr.themes.Soft()) as interface:
            gr.HTML("<h1>🛡️ Threat Intelligence Dashboard</h1>")
            
            with gr.Tabs():
                with gr.Tab("🔴 Live Feed"):
                    threat_display = gr.HTML(value=self.get_threat_summary)
                    refresh_btn = gr.Button("🔄 Refresh Feeds", variant="primary")
                    status_display = gr.HTML()
                
                with gr.Tab("📊 Analytics"):
                    stats_display = gr.HTML(value=self.get_statistics)
                    refresh_stats_btn = gr.Button("🔄 Refresh Statistics")

                with gr.Tab("🔍 IOC Search"):
                    ioc_input = gr.Textbox(label="Search IOCs", placeholder="IP, domain, hash...")
                    search_btn = gr.Button("🔍 Search")
                    ioc_results = gr.HTML()

            refresh_btn.click(self.refresh_feeds, outputs=[threat_display, status_display])
            refresh_stats_btn.click(self.get_statistics, outputs=stats_display)
            search_btn.click(self.search_iocs, inputs=ioc_input, outputs=ioc_results)
            ioc_input.submit(self.search_iocs, inputs=ioc_input, outputs=ioc_results)

        interface.launch(server_port=Config.GRADIO_PORT, share=Config.GRADIO_SHARE)

# --- Main Execution ---
def main():
    """Main entry point"""
    logger.info("🚀 Initializing Threat Intelligence Aggregator...")
    aggregator = ThreatIntelAggregator()
    dashboard = SimpleThreatDashboard(aggregator)
    
    logger.info(f"🚀 Launching dashboard on http://127.0.0.1:{Config.GRADIO_PORT}")
    dashboard.launch()

if __name__ == "__main__":
    main()
    