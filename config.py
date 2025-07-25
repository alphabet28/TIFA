"""
Configuration settings for the Threat Intelligence Aggregator
"""

import os
from typing import List, Dict
from pathlib import Path

# Load environment variables from .env file
def load_env_file():
    """Load environment variables from .env file if it exists"""
    env_file = Path(__file__).parent / '.env'
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip('"\'')
                    os.environ[key] = value

# Load .env file
load_env_file()

class Config:
    """Configuration settings for the Threat Intelligence Aggregator"""
    
    # RSS/Atom feeds for threat intelligence
    THREAT_FEEDS = [
        {
            'name': 'US-CERT CISA',
            'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
            'type': 'rss'
        },
        {
            'name': 'SANS Internet Storm Center',
            'url': 'https://isc.sans.edu/rssfeed.xml',
            'type': 'rss'
        },
        {
            'name': 'Krebs on Security',
            'url': 'https://krebsonsecurity.com/feed/',
            'type': 'rss'
        },
        {
            'name': 'Malware Bytes Labs',
            'url': 'https://blog.malwarebytes.com/feed/',
            'type': 'rss'
        },
        {
            'name': 'Threat Post',
            'url': 'https://threatpost.com/feed/',
            'type': 'rss'
        }
    ]
    
    # IOC extraction patterns
    IOC_PATTERNS = {
        'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'domains': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'urls': r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
        'md5_hashes': r'\b[a-fA-F0-9]{32}\b',
        'sha1_hashes': r'\b[a-fA-F0-9]{40}\b',
        'sha256_hashes': r'\b[a-fA-F0-9]{64}\b',
        'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'cve_ids': r'CVE-\d{4}-\d{4,7}',
        'file_paths': r'(?:[A-Za-z]:\\|/)(?:[^\\/:*?"<>|\r\n]+[\\\/])*[^\\/:*?"<>|\r\n]*',
    }
    
    # Database configuration
    DATABASE_PATH = "threat_intel.db"
    
    # Threat keywords for tagging
    THREAT_KEYWORDS = {
        'malware', 'ransomware', 'phishing', 'apt', 'vulnerability', 'exploit',
        'botnet', 'trojan', 'backdoor', 'rootkit', 'spyware', 'adware',
        'ddos', 'mitm', 'injection', 'xss', 'csrf', 'rce', 'lfi', 'rfi',
        'zero-day', 'patch', 'update', 'breach', 'leak', 'stolen', 'compromised'
    }
    
    # Severity assessment keywords
    HIGH_SEVERITY_KEYWORDS = ['critical', 'severe', 'urgent', 'zero-day', 'worm', 'ransomware']
    MEDIUM_SEVERITY_KEYWORDS = ['vulnerability', 'exploit', 'malware', 'phishing']
    
    # Common domains to exclude from IOC extraction
    EXCLUDE_DOMAINS = {
        'github.com', 'twitter.com', 'facebook.com', 'google.com', 
        'microsoft.com', 'apple.com', 'amazon.com', 'example.com',
        'localhost', 'www.w3.org'
    }
    
    # Application settings
    APP_TITLE = os.getenv("APP_TITLE", "Threat Intelligence Feed Aggregator")
    APP_DESCRIPTION = os.getenv("APP_DESCRIPTION", "AI-powered threat intelligence aggregation and analysis platform")
    
    # Server configuration
    SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
    SERVER_PORT = int(os.getenv("SERVER_PORT", "7860"))
    
    # Processing limits
    MAX_ITEMS_PER_FEED = int(os.getenv("MAX_ITEMS_PER_FEED", "20"))
    MAX_RECENT_THREATS = int(os.getenv("MAX_RECENT_THREATS", "50"))
    MAX_SEARCH_RESULTS = int(os.getenv("MAX_SEARCH_RESULTS", "50"))
    MAX_EXPORT_ITEMS = int(os.getenv("MAX_EXPORT_ITEMS", "100"))
    
    # Auto-refresh interval (seconds)
    AUTO_REFRESH_INTERVAL = int(os.getenv("AUTO_REFRESH_INTERVAL", "300"))  # 5 minutes
    
    # Thread pool configuration
    MAX_FEED_WORKERS = int(os.getenv("MAX_FEED_WORKERS", "5"))
    
    # Database configuration
    DATABASE_PATH = os.getenv("DATABASE_PATH", "threat_intel.db")
    
    # AI Configuration - Google Gemini Integration
    AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini")
    
    # Multiple API keys for rate limit handling - Load from environment
    GEMINI_API_KEYS = [
        key for key in [
            os.getenv("GEMINI_API_KEY_1"),
            os.getenv("GEMINI_API_KEY_2"),
            os.getenv("GEMINI_API_KEY_3"),  # Optional third key
            os.getenv("GEMINI_API_KEY_4"),  # Optional fourth key
        ] if key  # Only include non-None keys
    ]
    
    # Fallback keys if environment variables are not set (for development)
    if not GEMINI_API_KEYS:
        import warnings
        warnings.warn("No Gemini API keys found in environment variables. Using fallback configuration.")
        GEMINI_API_KEYS = [
            "AIzaSyDPqPeQvOq_YFJ5ThF75XYDKB7OO0qWPqg",
            "AIzaSyBAk1wMBqJHQHQtX1aGxUTQFBNTRPiMYdY"
        ]
    
    # Gemini model configuration (in order of preference - best to least)
    GEMINI_MODELS = [
        {
            "name": "gemini-2.5-flash",
            "rpm": 10,
            "tpm": 250000,
            "rpd": 250,
            "priority": 1
        },
        {
            "name": "gemini-2.5-flash-lite",
            "rpm": 15,
            "tpm": 250000,
            "rpd": 1000,
            "priority": 2
        },
        {
            "name": "gemini-2.0-flash",
            "rpm": 15,
            "tpm": 1000000,
            "rpd": 200,
            "priority": 3
        },
        {
            "name": "gemini-2.0-flash-lite",
            "rpm": 30,
            "tpm": 1000000,
            "rpd": 200,
            "priority": 4
        }
    ]
    
    # AI request configuration
    AI_REQUEST_TIMEOUT = int(os.getenv("AI_REQUEST_TIMEOUT", "45"))  # Increased timeout
    AI_MAX_RETRIES = int(os.getenv("AI_MAX_RETRIES", "5"))  # More retries
    AI_RETRY_DELAY = int(os.getenv("AI_RETRY_DELAY", "1"))  # Shorter base delay
    
    # Rate limiting (more lenient)
    RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
    MAX_CONCURRENT_AI_REQUESTS = int(os.getenv("MAX_CONCURRENT_AI_REQUESTS", "6"))  # Increased concurrent requests
