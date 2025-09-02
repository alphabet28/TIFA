"""
Elite Threat Intelligence Feed Aggregator Configuration
World-Class Enterprise Grade Platform for International Hackathon Competition
"""
import os
import random
from typing import List, Dict
from dotenv import load_dotenv

class Config:
    """Advanced configuration with enterprise-grade features and AI load balancing."""
    load_dotenv()

    # --- Multi-API Key Load Balancing System ---
    # Enhanced API key detection for both local and Streamlit Cloud environments
    GEMINI_API_KEYS = []
    
    # Method 1: Try Streamlit secrets (for Streamlit Cloud)
    try:
        import streamlit as st
        if hasattr(st, 'secrets'):
            potential_keys = [
                st.secrets.get("GEMINI_API_KEY_1"),
                st.secrets.get("GEMINI_API_KEY_2"),
                st.secrets.get("GEMINI_API_KEY"),  # Single key fallback
            ]
            GEMINI_API_KEYS.extend([key for key in potential_keys if key and key.strip()])
    except (ImportError, AttributeError, Exception):
        pass
    
    # Method 2: Try environment variables (for local development and fallback)
    env_keys = [
        os.getenv("GEMINI_API_KEY_1"),
        os.getenv("GEMINI_API_KEY_2"),
        os.getenv("GEMINI_API_KEY"),  # Single key fallback
    ]
    GEMINI_API_KEYS.extend([key for key in env_keys if key and key.strip()])
    
    # Remove duplicates while preserving order
    seen = set()
    unique_keys = []
    for key in GEMINI_API_KEYS:
        if key not in seen:
            seen.add(key)
            unique_keys.append(key)
    GEMINI_API_KEYS = unique_keys
    
    @classmethod
    def get_active_api_key_count(cls) -> int:
        """Get the actual count of active/valid API keys."""
        valid_keys = []
        for key in cls.GEMINI_API_KEYS:
            if key and key.strip() and len(key.strip()) > 20:  # Basic validation
                valid_keys.append(key)
        return len(valid_keys)
    
    @classmethod 
    def get_api_key_status(cls) -> dict:
        """Get detailed API key status for debugging."""
        return {
            "total_configured": len(cls.GEMINI_API_KEYS),
            "valid_keys": cls.get_active_api_key_count(),
            "has_streamlit_secrets": False,
            "has_env_vars": any(os.getenv(f"GEMINI_API_KEY_{i}") for i in [1, 2]) or bool(os.getenv("GEMINI_API_KEY")),
            "key_sources": []
        }
    
    # Advanced AI Model Options for Different Tasks
    GEMINI_MODELS = {
        "summary": "gemini-2.5-flash",      # Latest and fastest for summaries
        "analysis": "gemini-2.5-flash-lite",          # Latest experimental for deep analysis
        "classification": "gemini-2.0-flash-lite", # Quick classification
        "correlation": "gemini-2.0-flash"        # Complex correlations
    }

    # --- AI Configuration ---
    AI_PROVIDER = "gemini"
    
    @classmethod
    def get_random_api_key(cls) -> str | None:
        """Returns a random API key for load balancing."""
        return random.choice(cls.GEMINI_API_KEYS) if cls.GEMINI_API_KEYS else None

    # --- Elite Threat Intelligence Sources ---
    THREAT_FEEDS = [
        # Government & Official Sources
        {"name": "🏛️ US-CERT CISA", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "category": "government", "priority": "critical"},
        {"name": "🏛️ NIST NVD", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "category": "government", "priority": "high"},
        {"name": "🏛️ FBI IC3", "url": "https://www.ic3.gov/RSS/rss.xml", "category": "government", "priority": "critical"},
        
        # Premium Threat Intelligence
        {"name": "🎯 SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "category": "threat_intel", "priority": "high"},
        {"name": "🎯 MITRE ATT&CK", "url": "https://attack.mitre.org/resources/updates/updates.xml", "category": "threat_intel", "priority": "critical"},
        {"name": "🎯 AlienVault OTX", "url": "https://otx.alienvault.com/api/v1/pulses/subscribed", "category": "threat_intel", "priority": "high"},
        
        # Security Research & Blogs
        {"name": "🔬 Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "category": "research", "priority": "medium"},
        {"name": "🔬 MalwareBytes Labs", "url": "https://blog.malwarebytes.com/feed/", "category": "research", "priority": "medium"},
        {"name": "🔬 ThreatPost", "url": "https://threatpost.com/feed/", "category": "news", "priority": "medium"},
        {"name": "🔬 BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "category": "news", "priority": "medium"},
        {"name": "🔬 SecurityWeek", "url": "https://www.securityweek.com/rss", "category": "news", "priority": "medium"},
        
        # Vulnerability Databases
        {"name": "🚨 Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "category": "exploits", "priority": "high"},
        {"name": "🚨 VulnDB", "url": "https://vuldb.com/rss/?type=updates", "category": "vulnerabilities", "priority": "high"},
        
        # Dark Web & Underground
        {"name": "🕵️ ThreatMiner", "url": "https://www.threatminer.org/rss.xml", "category": "darkweb", "priority": "high"},
        {"name": "🕵️ HackerNews", "url": "https://thehackernews.com/feeds/posts/default", "category": "news", "priority": "medium"},
    ]

    # --- Database Configuration ---
    # Try to use a writable location, fallback to memory database if needed
    DB_PATH = os.getenv("DATABASE_PATH", "data/threat_intel.db")
    
    # For Streamlit Cloud deployment, check if we can write to the specified path
    try:
        import tempfile
        db_dir = os.path.dirname(DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            # Try to create the directory
            try:
                os.makedirs(db_dir, exist_ok=True)
            except (OSError, PermissionError):
                # If we can't create the data directory, use temp directory
                DB_PATH = os.path.join(tempfile.gettempdir(), "threat_intel.db")
        elif db_dir and not os.access(db_dir, os.W_OK):
            # If directory exists but not writable, use temp directory
            DB_PATH = os.path.join(tempfile.gettempdir(), "threat_intel.db")
    except Exception:
        # Ultimate fallback - use memory database
        pass
    
    # --- Advanced Application Settings ---
    APP_TITLE = os.getenv("APP_TITLE", "🛡️ TIFA - Elite Threat Intelligence Aggregator")
    APP_DESCRIPTION = os.getenv("APP_DESCRIPTION", "AI-Powered Global Threat Intelligence Platform")
    APP_ICON = "🛡️"
    
    # --- Performance & Scaling ---
    MAX_ITEMS_PER_FEED = int(os.getenv("MAX_ITEMS_PER_FEED", 50))
    MAX_RECENT_THREATS = int(os.getenv("MAX_RECENT_THREATS", 100))
    MAX_SEARCH_RESULTS = int(os.getenv("MAX_SEARCH_RESULTS", 100))
    MAX_EXPORT_ITEMS = int(os.getenv("MAX_EXPORT_ITEMS", 1000))
    AUTO_REFRESH_INTERVAL = int(os.getenv("AUTO_REFRESH_INTERVAL", 300))
    
    # --- Domain Filtering ---
    EXCLUDE_DOMAINS = {
        "w3.org", "schema.org", "example.com", "localhost", "github.com",
        "twitter.com", "facebook.com", "google.com", "microsoft.com",
        "cve.mitre.org", "nvd.nist.gov"
    }
    
    # --- AI Processing Configuration ---
    AI_REQUEST_TIMEOUT = int(os.getenv("AI_REQUEST_TIMEOUT", 45))
    AI_MAX_RETRIES = int(os.getenv("AI_MAX_RETRIES", 5))
    AI_RETRY_DELAY = int(os.getenv("AI_RETRY_DELAY", 1))
    MAX_CONCURRENT_AI_REQUESTS = int(os.getenv("MAX_CONCURRENT_AI_REQUESTS", 10))
    
    # --- Rate Limiting ---
    RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", 60))
    
    # --- Server Configuration ---
    SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
    SERVER_PORT = int(os.getenv("SERVER_PORT", 7860))
    
    # --- Enhanced IOC Patterns for SOC Teams ---
    IOC_PATTERNS = {
        # Network Indicators
        "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "ipv6": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "domain": r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,})\b',
        "subdomain": r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}\b',
        "url": r'https?://[^\s/$.?#].[^\s]*',
        "ftp_url": r'ftp://[^\s/$.?#].[^\s]*',
        
        # File Hashes
        "md5": r'\b[A-Fa-f0-9]{32}\b',
        "sha1": r'\b[A-Fa-f0-9]{40}\b',
        "sha256": r'\b[A-Fa-f0-9]{64}\b',
        "sha512": r'\b[A-Fa-f0-9]{128}\b',
        "ssdeep": r'\b\d+:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\b',
        
        # Vulnerabilities & CVEs
        "cve": r'CVE-\d{4}-\d{4,7}',
        "cwe": r'CWE-\d+',
        "cpe": r'cpe:2\.3:[aho\*\-]:[^\s:]*(?::[^\s:]*){8}',
        
        # Email & Communication
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "phone": r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
        
        # Cryptocurrency
        "bitcoin": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "ethereum": r'\b0x[a-fA-F0-9]{40}\b',
        "monero": r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
        
        # Malware & Signatures
        "yara_rule": r'rule\s+\w+\s*\{[^}]*\}',
        "mutex": r'Global\\[A-Za-z0-9_-]+',
        "service_name": r'(?:HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\)([A-Za-z0-9_-]+)',
        
        # File System
        "windows_path": r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        "unix_path": r'(?:/[^/\s]+)+/?',
        "filename": r'\b[A-Za-z0-9_.-]+\.(?:exe|dll|bat|cmd|ps1|vbs|jar|zip|rar|doc|docx|pdf|xls|xlsx|ppt|pptx)\b',
        "pdb_path": r'[A-Za-z]:\\[^:]+\.pdb',
        
        # Registry
        "registry_key": r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*',
        "registry_value": r'(?:HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*\\)([^\\]+)',
        
        # Network & Infrastructure
        "user_agent": r'User-Agent:\s*([^\r\n]+)',
        "http_header": r'[A-Za-z-]+:\s*[^\r\n]+',
        "mac_address": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
        "port": r'\b(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\b',
        
        # Attack Patterns
        "attack_pattern": r'T\d{4}(?:\.\d{3})?',  # MITRE ATT&CK
        "malware_family": r'\b(?:emotet|trickbot|ryuk|cobalt.*strike|metasploit|mimikatz|powershell.*empire)\b',
        
        # Cloud & Modern Infrastructure
        "aws_access_key": r'AKIA[0-9A-Z]{16}',
        "gcp_key": r'AIza[0-9A-Za-z\\-_]{35}',
        "docker_image": r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[a-z0-9]+(?:[._-][a-z0-9]+)*',
        
        # Mobile & IoT
        "android_package": r'[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+',
        "ios_bundle": r'[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+',
        
        # Certificates & Encryption
        "ssl_cert_serial": r'\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){7,19}\b',
        "base64_encoded": r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    }
