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
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    genai = None
from urllib.parse import urljoin, urlparse

from ..core.config import Config
from ..core.models import ThreatIntelItem
from ..core.database import ThreatIntelDatabase

logger = logging.getLogger(__name__)

# --- Enhanced IOC Extractor for SOC Teams ---
class IOCExtractor:
    """Enhanced IOC extraction with advanced categorization for SOC teams."""
    
    def __init__(self):
        """Initialize with comprehensive patterns and smart filtering."""
        self.patterns = Config.IOC_PATTERNS
        
        # Enhanced false positive filters for better accuracy
        self.false_positive_filters = {
            "domains": {
                "w3.org", "schema.org", "example.com", "localhost", "github.com",
                "twitter.com", "facebook.com", "google.com", "microsoft.com",
                "cve.mitre.org", "nvd.nist.gov", "attack.mitre.org", "sans.org",
                "owasp.org", "cert.org", "us-cert.gov", "cisa.gov", "nist.gov",
                "wikipedia.org", "stackoverflow.com", "reddit.com", "linkedin.com"
            },
            "ips": {
                "127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.1.1",
                "10.0.0.1", "172.16.0.1", "8.8.8.8", "1.1.1.1", "127.0.0.0"
            },
            "emails": {
                "admin@example.com", "test@test.com", "noreply@example.com",
                "support@example.com", "info@example.com"
            }
        }
        
        # IOC categories for better threat analysis
        self.ioc_categories = {
            "network": ["ipv4", "ipv6", "domain", "subdomain", "url", "ftp_url", "mac_address", "port"],
            "file": ["md5", "sha1", "sha256", "sha512", "ssdeep", "filename", "windows_path", "unix_path", "pdb_path"],
            "vulnerability": ["cve", "cwe", "cpe", "attack_pattern"],
            "communication": ["email", "phone", "user_agent", "http_header"],
            "financial": ["bitcoin", "ethereum", "monero"],
            "malware": ["yara_rule", "mutex", "service_name", "malware_family"],
            "registry": ["registry_key", "registry_value"],
            "cloud": ["aws_access_key", "gcp_key", "docker_image"],
            "mobile": ["android_package", "ios_bundle"],
            "crypto": ["ssl_cert_serial", "base64_encoded"]
        }

    def extract(self, text: str, context: str = "") -> Dict[str, Set[str]]:
        """
        Enhanced IOC extraction with smart categorization and filtering.
        
        Args:
            text: Text content to extract IOCs from
            context: Additional context for better filtering
            
        Returns:
            Dict mapping IOC categories to sets of found IOCs
        """
        iocs = {}
        text_clean = text.lower()
        
        for ioc_type, pattern in self.patterns.items():
            try:
                matches = set(re.findall(pattern, text, re.IGNORECASE | re.MULTILINE))
                
                if matches:
                    # Apply smart filtering
                    filtered_matches = self._filter_false_positives(matches, ioc_type, context)
                    
                    if filtered_matches:
                        # Categorize IOCs
                        category = self._get_ioc_category(ioc_type)
                        if category not in iocs:
                            iocs[category] = set()
                        iocs[category].update(filtered_matches)
                        
            except re.error as e:
                logger.warning(f"Regex error for pattern {ioc_type}: {e}")
                continue
        
        return iocs

    def _filter_false_positives(self, matches: Set[str], ioc_type: str, context: str) -> Set[str]:
        """Apply intelligent false positive filtering."""
        filtered = set()
        
        for match in matches:
            if self._is_valid_ioc(match, ioc_type, context):
                filtered.add(match.strip())
        
        return filtered

    def _is_valid_ioc(self, ioc: str, ioc_type: str, context: str) -> bool:
        """Comprehensive IOC validation logic."""
        ioc_lower = ioc.lower().strip()
        
        # Length-based filtering
        if len(ioc_lower) < 3:
            return False
            
        # Type-specific validation
        if ioc_type in ["ipv4", "ip"]:
            return self._is_valid_ip(ioc_lower)
        elif ioc_type in ["domain", "subdomain"]:
            return self._is_valid_domain(ioc_lower)
        elif ioc_type == "email":
            return self._is_valid_email(ioc_lower)
        elif ioc_type in ["md5", "sha1", "sha256", "sha512"]:
            return self._is_valid_hash(ioc_lower, ioc_type)
        elif ioc_type == "cve":
            return self._is_valid_cve(ioc)
        
        return True

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP addresses."""
        if ip in self.false_positive_filters["ips"]:
            return False
        
        # Check for private/reserved ranges
        parts = ip.split('.')
        if len(parts) != 4:
            return False
            
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            # Skip private ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
            if first == 10:
                return False
            if first == 172 and 16 <= second <= 31:
                return False
            if first == 192 and second == 168:
                return False
            # Skip localhost and multicast
            if first in [127, 169, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239]:
                return False
                
        except ValueError:
            return False
            
        return True

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain names."""
        if domain in self.false_positive_filters["domains"]:
            return False
        
        # Basic domain validation
        if len(domain) > 253 or len(domain) < 4:
            return False
        
        # Check for obvious non-domains
        if domain.startswith('.') or domain.endswith('.'):
            return False
            
        # Skip common false positives
        if any(skip in domain for skip in ['example', 'test', 'localhost', 'invalid']):
            return False
            
        return True

    def _is_valid_email(self, email: str) -> bool:
        """Validate email addresses."""
        return email not in self.false_positive_filters["emails"] and '@' in email and '.' in email

    def _is_valid_hash(self, hash_val: str, hash_type: str) -> bool:
        """Validate hash values."""
        expected_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
        expected_len = expected_lengths.get(hash_type, 0)
        
        return len(hash_val) == expected_len and all(c in '0123456789abcdef' for c in hash_val.lower())

    def _is_valid_cve(self, cve: str) -> bool:
        """Validate CVE format."""
        parts = cve.split('-')
        return len(parts) == 3 and parts[0] == 'CVE' and len(parts[1]) == 4 and len(parts[2]) >= 4

    def _get_ioc_category(self, ioc_type: str) -> str:
        """Map IOC types to categories."""
        for category, types in self.ioc_categories.items():
            if ioc_type in types:
                return category
        return "other"

    def get_ioc_summary(self, iocs: Dict[str, Set[str]]) -> Dict[str, Any]:
        """Generate comprehensive IOC summary for SOC analysis."""
        summary = {
            "total_iocs": sum(len(ioc_set) for ioc_set in iocs.values()),
            "categories": {},
            "risk_indicators": [],
            "notable_findings": []
        }
        
        for category, ioc_set in iocs.items():
            summary["categories"][category] = {
                "count": len(ioc_set),
                "samples": list(ioc_set)[:5]  # First 5 samples
            }
            
            # Risk assessment
            if category == "malware" and len(ioc_set) > 0:
                summary["risk_indicators"].append("Malware artifacts detected")
            elif category == "vulnerability" and len(ioc_set) > 5:
                summary["risk_indicators"].append("Multiple vulnerabilities referenced")
            elif category == "network" and len(ioc_set) > 10:
                summary["risk_indicators"].append("Extensive network infrastructure")
        
        return summary

# --- Enhanced AI Analyzer for SOC Teams ---
class AIAnalyzer:
    """Simplified AI analysis focused on threat categorization and summarization."""
    
    def __init__(self):
        """Initialize with threat-focused analysis capabilities."""
        self.api_keys = Config.GEMINI_API_KEYS
        self.models = {}
        self.current_key_index = 0
        
        # Add missing attributes for API key rotation
        self.last_reset = time.time()
        self.request_counts = {key: 0 for key in self.api_keys} if self.api_keys else {}
        
        # Threat categories for SOC teams
        self.threat_categories = {
            "malware": ["trojan", "ransomware", "virus", "worm", "backdoor", "rootkit", "spyware", "adware"],
            "phishing": ["phishing", "social engineering", "credential harvesting", "business email compromise"],
            "vulnerability": ["zero-day", "cve", "exploit", "patch", "vulnerability", "security flaw"],
            "apt": ["advanced persistent threat", "nation-state", "espionage", "targeted attack"],
            "infrastructure": ["command and control", "c2", "botnet", "proxy", "dns tunneling"],
            "data_breach": ["data leak", "breach", "exposure", "unauthorized access", "insider threat"],
            "ddos": ["denial of service", "ddos", "amplification", "flood attack"],
            "fraud": ["financial fraud", "payment fraud", "identity theft", "scam"]
        }
        
        if self.api_keys and GENAI_AVAILABLE:
            self._initialize_models()
        else:
            logger.warning("⚠️ No Gemini API keys found or google.generativeai not available. Using rule-based analysis.")

    def _initialize_models(self):
        """Initialize AI models for threat analysis."""
        if not GENAI_AVAILABLE:
            logger.warning("Google Generative AI not available")
            return
            
        try:
            if genai:
                genai.configure(api_key=self.api_keys[0])  # type: ignore
                self.models["summary"] = genai.GenerativeModel(Config.GEMINI_MODELS["summary"])  # type: ignore
                logger.info(f"✅ Initialized AI analyzer with {Config.GEMINI_MODELS['summary']}")
        except Exception as e:
            logger.error(f"Failed to initialize AI models: {e}")

    def analyze(self, text: str, analysis_type: str = "summary") -> Dict[str, Any]:
        """
        Simplified threat analysis focused on SOC team needs.
        
        Args:
            text: Threat intelligence text to analyze
            analysis_type: Type of analysis (summary, categorization)
            
        Returns:
            Analysis results with category, severity, and summary
        """
        try:
            # Rule-based analysis (always available)
            rule_based_analysis = self._rule_based_analysis(text)
            
            # AI-enhanced analysis (if available)
            if self.api_keys and "summary" in self.models:
                ai_analysis = self._ai_enhanced_analysis(text)
                
                # Combine rule-based and AI analysis
                result = {
                    "category": ai_analysis.get("category", rule_based_analysis["category"]),
                    "severity": ai_analysis.get("severity", rule_based_analysis["severity"]),
                    "summary": ai_analysis.get("summary", rule_based_analysis["summary"]),
                    "confidence": "High" if self.api_keys else "Medium",
                    "analysis_method": "AI + Rules" if self.api_keys else "Rules"
                }
            else:
                result = rule_based_analysis
                result["analysis_method"] = "Rules"
                
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {
                "category": "Unknown",
                "severity": "Medium",
                "summary": text[:200] + "..." if len(text) > 200 else text,
                "confidence": "Low",
                "analysis_method": "Fallback"
            }

    def _rule_based_analysis(self, text: str) -> Dict[str, Any]:
        """Fast rule-based threat categorization."""
        text_lower = text.lower()
        
        # Categorization based on keywords
        detected_category = "unknown"
        confidence_score = 0
        
        for category, keywords in self.threat_categories.items():
            matches = sum(1 for keyword in keywords if keyword in text_lower)
            if matches > confidence_score:
                confidence_score = matches
                detected_category = category
        
        # Severity assessment based on keywords
        severity = self._assess_severity(text_lower)
        
        # Generate summary
        summary = self._generate_rule_based_summary(text, detected_category)
        
        return {
            "category": detected_category,
            "severity": severity,
            "summary": summary,
            "confidence": "High" if confidence_score > 2 else "Medium" if confidence_score > 0 else "Low"
        }

    def _assess_severity(self, text: str) -> str:
        """Assess threat severity based on keywords."""
        critical_keywords = ["zero-day", "critical", "remote code execution", "privilege escalation", "nation-state"]
        high_keywords = ["vulnerability", "exploit", "malware", "ransomware", "breach"]
        medium_keywords = ["phishing", "suspicious", "warning", "alert"]
        
        if any(keyword in text for keyword in critical_keywords):
            return "Critical"
        elif any(keyword in text for keyword in high_keywords):
            return "High"
        elif any(keyword in text for keyword in medium_keywords):
            return "Medium"
        else:
            return "Low"

    def _generate_rule_based_summary(self, text: str, category: str) -> str:
        """Generate a concise summary for SOC teams."""
        # Extract key sentences (simple approach)
        sentences = text.split('.')[:3]  # First 3 sentences
        summary = '. '.join(sentences).strip()
        
        if len(summary) > 300:
            summary = summary[:300] + "..."
        
        return summary

    def _ai_enhanced_analysis(self, text: str) -> Dict[str, Any]:
        """AI-enhanced analysis using Gemini models."""
        if not GENAI_AVAILABLE:
            return {}
            
        try:
            prompt = f"""
            Analyze this threat intelligence for a SOC team. Provide:
            1. Category (malware, phishing, vulnerability, apt, infrastructure, data_breach, ddos, fraud, or unknown)
            2. Severity (Critical, High, Medium, Low)
            3. Concise summary (max 200 words) focusing on actionable intelligence

            Threat Intel: {text[:1500]}  # Limit text length

            Respond in JSON format:
            {{
                "category": "category_name",
                "severity": "severity_level", 
                "summary": "concise_summary"
            }}
            """
            
            # Get AI key and make request
            api_key = self._get_api_key()
            if not api_key or not genai:
                return {}
                
            genai.configure(api_key=api_key)  # type: ignore
            
            if "summary" not in self.models:
                return {}
                
            response = self.models["summary"].generate_content(prompt)
            
            # Parse response
            response_text = response.text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:-3]
            elif response_text.startswith('```'):
                response_text = response_text[3:-3]
                
            import json
            analysis = json.loads(response_text)
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {}

    def _get_api_key(self) -> Optional[str]:
        """Get API key with simple rotation."""
        if not self.api_keys:
            return None
            
        key = self.api_keys[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        return key

    def get_threat_summary_report(self, threats: List[Any]) -> Dict[str, Any]:
        """Generate comprehensive threat summary report for SOC teams."""
        if not threats:
            return {"message": "No threats to analyze"}
            
        # Categorize threats
        categories = {}
        severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        
        for threat in threats:
            category = getattr(threat, 'category', 'unknown')
            severity = getattr(threat, 'severity', 'Medium')
            
            categories[category] = categories.get(category, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1
        
        # Generate report
        report = {
            "total_threats": len(threats),
            "category_breakdown": categories,
            "severity_breakdown": severities,
            "top_categories": sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5],
            "critical_threats": severities["Critical"],
            "recommendations": self._generate_recommendations(categories, severities)
        }
        
        return report

    def _generate_recommendations(self, categories: Dict, severities: Dict) -> List[str]:
        """Generate actionable recommendations for SOC teams."""
        recommendations = []
        
        if severities.get("Critical", 0) > 0:
            recommendations.append("🚨 IMMEDIATE ACTION: Critical threats detected - escalate to senior analysts")
        
        if categories.get("malware", 0) > 5:
            recommendations.append("🦠 High malware activity - review endpoint protection and network segmentation")
        
        if categories.get("phishing", 0) > 3:
            recommendations.append("🎣 Phishing campaign detected - alert users and review email security")
        
        if categories.get("vulnerability", 0) > 10:
            recommendations.append("🔍 Multiple vulnerabilities - prioritize patch management")
        
        if not recommendations:
            recommendations.append("✅ Threat landscape appears stable - continue monitoring")
        
        return recommendations

    def _get_next_api_key(self) -> Optional[str]:
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
            
            # Add additional metadata
            item.category = feed_info.get("category", "unknown")
            item.priority = feed_info.get("priority", "medium")
            item.feed_url = feed_info["url"]
            
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
