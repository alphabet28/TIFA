"""
Elite Threat Intelligence Core Engine
Advanced AI-Powered IOC Extraction, Analysis, and Feed Collection
World-Class Enterprise Platform for International Competition
"""
import re
import json
import asyncio
import aiohttp
import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Set, Any, List, Optional, Tuple
import feedparser
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import google.generativeai as genai
from urllib.parse import urljoin, urlparse

from config import Config
from models import ThreatIntelItem
from database import ThreatIntelDatabase

logger = logging.getLogger(__name__)

# --- Advanced IOC Extractor ---
class IOCExtractor:
    """Elite IOC extraction with ML-enhanced pattern matching and context analysis."""
    
    def __init__(self):
        """Initialize with advanced patterns and context rules."""
        self.patterns = Config.IOC_PATTERNS
        self.false_positive_filters = {
            "domain": {
                "w3.org", "schema.org", "example.com", "localhost", "github.com",
                "twitter.com", "facebook.com", "google.com", "microsoft.com",
                "cve.mitre.org", "nvd.nist.gov"
            },
            "ip": {
                "127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.1.1",
                "10.0.0.1", "172.16.0.1"
            }
        }

    def extract(self, text: str, context: str = "") -> Dict[str, Set[str]]:
        """
        Advanced IOC extraction with context analysis and false positive filtering.
        
        Args:
            text: The text content to analyze
            context: Additional context for better IOC validation
            
        Returns:
            Dictionary with categorized IOCs
        """
        iocs = {}
        text_lower = text.lower()
        
        for ioc_type, pattern in self.patterns.items():
            matches = set(re.findall(pattern, text, re.IGNORECASE))
            
            # Apply context-aware filtering
            filtered_matches = self._filter_false_positives(matches, ioc_type, text_lower)
            iocs[ioc_type] = filtered_matches
            
        return iocs

    def _filter_false_positives(self, matches: Set[str], ioc_type: str, context: str) -> Set[str]:
        """Filter out common false positives based on context."""
        if ioc_type in self.false_positive_filters:
            matches -= self.false_positive_filters[ioc_type]
        
        # Additional contextual filtering
        filtered = set()
        for match in matches:
            if self._is_valid_ioc(match, ioc_type, context):
                filtered.add(match)
                
        return filtered

    def _is_valid_ioc(self, ioc: str, ioc_type: str, context: str) -> bool:
        """Validate IOC based on type and context."""
        if ioc_type == "ip":
            return self._is_valid_ip(ioc)
        elif ioc_type == "domain":
            return self._is_valid_domain(ioc, context)
        elif ioc_type in ["md5", "sha1", "sha256"]:
            return self._is_valid_hash(ioc)
        return True

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address."""
        parts = ip.split('.')
        try:
            return all(0 <= int(part) <= 255 for part in parts) and len(parts) == 4
        except ValueError:
            return False

    def _is_valid_domain(self, domain: str, context: str) -> bool:
        """Validate domain with context awareness."""
        if len(domain) < 4 or '.' not in domain:
            return False
        
        # Check if mentioned in threat context
        threat_keywords = ["malware", "phishing", "c2", "command", "control", "botnet", "suspicious"]
        return any(keyword in context for keyword in threat_keywords)

    def _is_valid_hash(self, hash_value: str) -> bool:
        """Validate hash format."""
        return hash_value.isalnum() and len(hash_value) in [32, 40, 64]

# --- Elite AI Analyzer with Load Balancing ---
class AIAnalyzer:
    """Advanced AI analysis with multi-model support and intelligent load balancing."""
    
    def __init__(self):
        """Initialize with multiple models and API key rotation."""
        self.api_keys = Config.GEMINI_API_KEYS
        self.models = {}
        self.current_key_index = 0
        self.request_counts = {key: 0 for key in self.api_keys}
        self.last_reset = time.time()
        
        if self.api_keys:
            self._initialize_models()
        else:
            logger.warning("⚠️ No Gemini API keys found. AI features will be disabled.")

    def _initialize_models(self):
        """Initialize different models for different tasks."""
        for task, model_name in Config.GEMINI_MODELS.items():
            try:
                # Use first API key for initialization
                genai.configure(api_key=self.api_keys[0])
                self.models[task] = genai.GenerativeModel(model_name)
                logger.info(f"✅ Initialized {model_name} for {task}")
            except Exception as e:
                logger.error(f"Failed to initialize {model_name}: {e}")

    def _get_next_api_key(self) -> str:
        """Intelligent API key rotation for load balancing."""
        if not self.api_keys:
            return None
            
        # Reset counters every hour
        if time.time() - self.last_reset > 3600:
            self.request_counts = {key: 0 for key in self.api_keys}
            self.last_reset = time.time()
        
        # Find the key with the least usage
        min_usage_key = min(self.request_counts.keys(), key=lambda k: self.request_counts[k])
        self.request_counts[min_usage_key] += 1
        
        return min_usage_key

    def analyze(self, content: str, analysis_type: str = "summary") -> Dict[str, Any]:
        """
        Advanced AI analysis with retry logic and fallback handling.
        
        Args:
            content: Content to analyze
            analysis_type: Type of analysis (summary, analysis, classification, correlation)
            
        Returns:
            Analysis results with summary, severity, category, and confidence
        """
        if not self.models:
            return self._fallback_analysis(content)

        api_key = self._get_next_api_key()
        if not api_key:
            return self._fallback_analysis(content)

        # Configure the selected API key
        genai.configure(api_key=api_key)
        
        prompt = self._build_advanced_prompt(content, analysis_type)
        
        for attempt in range(Config.AI_MAX_RETRIES):
            try:
                model = self.models.get(analysis_type, self.models.get("summary"))
                response = model.generate_content(prompt)
                
                # Parse and validate response
                result = self._parse_ai_response(response.text)
                if result:
                    result["api_key_used"] = api_key[-6:]  # Last 6 chars for debugging
                    result["analysis_type"] = analysis_type
                    return result
                    
            except Exception as e:
                logger.warning(f"AI analysis attempt {attempt + 1} failed: {e}")
                if attempt < Config.AI_MAX_RETRIES - 1:
                    time.sleep(Config.AI_RETRY_DELAY * (attempt + 1))
                    # Try next API key
                    api_key = self._get_next_api_key()
                    if api_key:
                        genai.configure(api_key=api_key)

        return self._fallback_analysis(content)

    def _build_advanced_prompt(self, content: str, analysis_type: str) -> str:
        """Build sophisticated prompts for different analysis types."""
        base_context = """You are an elite cybersecurity threat intelligence analyst with expertise in 
        advanced persistent threats, malware analysis, and threat hunting. Analyze the following threat intelligence."""
        
        prompts = {
            "summary": f"""{base_context}
            
            Provide:
            1. Concise executive summary (max 150 words)
            2. Threat severity (Critical/High/Medium/Low)
            3. Primary threat category (Malware/Phishing/Vulnerability/APT/Other)
            4. Confidence level (High/Medium/Low)
            5. Key IOCs mentioned
            6. Affected systems/platforms
            
            Content: {content}
            
            Respond in valid JSON format with keys: summary, severity, category, confidence, key_iocs, affected_systems""",
            
            "analysis": f"""{base_context}
            
            Perform deep technical analysis:
            1. Threat actor attribution possibilities
            2. Attack vector analysis
            3. Potential impact assessment
            4. Recommended mitigation strategies
            5. Related threats/campaigns
            
            Content: {content}
            
            Respond in valid JSON format.""",
            
            "classification": f"""{base_context}
            
            Classify this threat:
            1. MITRE ATT&CK tactics and techniques
            2. Kill chain phase
            3. Industry targeting
            4. Geographic targeting
            5. Sophistication level
            
            Content: {content}
            
            Respond in valid JSON format."""
        }
        
        return prompts.get(analysis_type, prompts["summary"])

    def _parse_ai_response(self, response_text: str) -> Optional[Dict[str, Any]]:
        """Parse and validate AI response."""
        try:
            # Clean the response
            cleaned = response_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            
            result = json.loads(cleaned)
            
            # Validate required fields
            if "summary" in result and "severity" in result:
                return result
                
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            
        return None

    def _fallback_analysis(self, content: str) -> Dict[str, Any]:
        """Fallback analysis when AI is unavailable."""
        # Simple keyword-based severity assessment
        severity = "Medium"
        if any(word in content.lower() for word in ["critical", "zero-day", "rce", "ransomware"]):
            severity = "Critical"
        elif any(word in content.lower() for word in ["high", "exploit", "malware", "breach"]):
            severity = "High"
        elif any(word in content.lower() for word in ["low", "advisory", "patch"]):
            severity = "Low"
        
        return {
            "summary": content[:500] + "..." if len(content) > 500 else content,
            "severity": severity,
            "category": "Unknown",
            "confidence": "Low",
            "key_iocs": [],
            "affected_systems": [],
            "analysis_type": "fallback"
        }

# --- High-Performance Feed Collector ---
class FeedCollector:
    """Enterprise-grade feed collection with concurrent processing and error handling."""
    
    def __init__(self, db: ThreatIntelDatabase, ioc_extractor: IOCExtractor):
        """Initialize with enhanced capabilities."""
        self.db = db
        self.ioc_extractor = ioc_extractor
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TIFA-ThreatIntel-Aggregator/1.0 (Enterprise Security Research)'
        })

    def collect_all_feeds(self) -> Dict[str, List[ThreatIntelItem]]:
        """Collect from all feeds using concurrent processing."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=Config.MAX_CONCURRENT_AI_REQUESTS) as executor:
            future_to_feed = {
                executor.submit(self.fetch_feed, feed_info): feed_info 
                for feed_info in Config.THREAT_FEEDS
            }
            
            for future in as_completed(future_to_feed):
                feed_info = future_to_feed[future]
                try:
                    items = future.result(timeout=Config.AI_REQUEST_TIMEOUT)
                    results[feed_info["name"]] = items
                    logger.info(f"✅ Collected {len(items)} items from {feed_info['name']}")
                except Exception as e:
                    logger.error(f"❌ Failed to collect from {feed_info['name']}: {e}")
                    results[feed_info["name"]] = []
                    
        return results

    def fetch_feed(self, feed_info: Dict[str, str]) -> List[ThreatIntelItem]:
        """Enhanced feed fetching with better error handling and parsing."""
        logger.info(f"Fetching feed: {feed_info['name']}")
        items = []
        
        try:
            # Enhanced feed parsing with timeout and retry logic
            response = self.session.get(
                feed_info["url"], 
                timeout=30,
                allow_redirects=True
            )
            response.raise_for_status()
            
            feed = feedparser.parse(response.content)
            
            if not feed.entries:
                logger.warning(f"No entries found in feed: {feed_info['name']}")
                return items
            
            for entry in feed.entries[:Config.MAX_ITEMS_PER_FEED]:
                item = self._process_feed_entry(entry, feed_info)
                if item:
                    items.append(item)
                    
        except Exception as e:
            logger.error(f"Failed to fetch feed '{feed_info['name']}': {e}")
            
        return items

    def _process_feed_entry(self, entry, feed_info: Dict[str, str]) -> Optional[ThreatIntelItem]:
        """Process individual feed entry with enhanced data extraction."""
        try:
            title = entry.get("title", "").strip()
            link = entry.get("link", "").strip()
            
            if not title or not link:
                return None

            # Create unique ID and check for duplicates
            item_id = f"{feed_info['name']}:{link}"
            if self.db.item_exists(item_id):
                return None

            # Enhanced summary extraction
            summary = self._extract_enhanced_summary(entry)
            
            # Better date parsing
            published_date = self._parse_publication_date(entry)
            
            # Enhanced IOC extraction with context
            full_text = f"{title} {summary}"
            iocs = self.ioc_extractor.extract(full_text, context=f"Source: {feed_info['name']}")
            
            # Create enhanced threat item
            item = ThreatIntelItem(
                title=title,
                link=link,
                summary=summary,
                source=feed_info["name"],
                published_date=published_date,
                iocs=iocs
            )
            
            return item
            
        except Exception as e:
            logger.error(f"Error processing feed entry: {e}")
            return None

    def _extract_enhanced_summary(self, entry) -> str:
        """Enhanced summary extraction with multiple fallbacks."""
        summary_sources = [
            entry.get("summary", ""),
            entry.get("description", ""),
            entry.get("content", [{}])[0].get("value", "") if entry.get("content") else "",
            "No summary available."
        ]
        
        for source in summary_sources:
            if source and source.strip():
                # Clean HTML and normalize text
                soup = BeautifulSoup(source, 'html.parser')
                text = soup.get_text()
                return ' '.join(text.split()).strip()[:1000]  # Limit to 1000 chars
                
        return "No summary available."

    def _parse_publication_date(self, entry) -> str:
        """Enhanced date parsing with multiple formats."""
        date_fields = ["published_parsed", "updated_parsed", "created_parsed"]
        
        for field in date_fields:
            parsed_time = entry.get(field)
            if parsed_time:
                try:
                    return datetime(*parsed_time[:6]).isoformat()
                except (TypeError, ValueError):
                    continue
        
        # Fallback to string parsing
        date_strings = [entry.get("published", ""), entry.get("updated", "")]
        for date_str in date_strings:
            if date_str:
                try:
                    # Try common formats
                    for fmt in ["%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S"]:
                        try:
                            return datetime.strptime(date_str[:25], fmt).isoformat()
                        except ValueError:
                            continue
                except Exception:
                    continue
                    
        return datetime.now().isoformat()

# --- Threat Correlation Engine ---
class ThreatCorrelator:
    """Advanced threat correlation and pattern detection."""
    
    def __init__(self, db: ThreatIntelDatabase):
        self.db = db
    
    def find_correlations(self, new_item: ThreatIntelItem) -> List[Dict[str, Any]]:
        """Find correlations with existing threats."""
        correlations = []
        
        # IOC-based correlations
        for ioc_type, iocs in new_item.iocs.items():
            for ioc in iocs:
                related_threats = self.db.search_ioc(ioc)
                if related_threats:
                    correlations.append({
                        "type": "ioc_overlap",
                        "ioc": ioc,
                        "ioc_type": ioc_type,
                        "related_threats": len(related_threats),
                        "confidence": "high"
                    })
        
        return correlations

# --- Real-time Alert System ---
class AlertSystem:
    """Real-time alerting for critical threats."""
    
    def __init__(self):
        self.alert_rules = [
            {"keywords": ["zero-day", "0-day"], "severity": "critical"},
            {"keywords": ["ransomware", "encryption"], "severity": "high"},
            {"keywords": ["apt", "advanced persistent"], "severity": "high"},
            {"keywords": ["breach", "compromise"], "severity": "medium"}
        ]
    
    def check_alerts(self, item: ThreatIntelItem) -> List[Dict[str, Any]]:
        """Check if item triggers any alerts."""
        alerts = []
        content = f"{item.title} {item.summary}".lower()
        
        for rule in self.alert_rules:
            if any(keyword in content for keyword in rule["keywords"]):
                alerts.append({
                    "rule": rule,
                    "triggered_keywords": [kw for kw in rule["keywords"] if kw in content],
                    "severity": rule["severity"],
                    "timestamp": datetime.now().isoformat()
                })
        
        return alerts
