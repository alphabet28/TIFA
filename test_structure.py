#!/usr/bin/env python3
"""
Test script to verify the reorganized TIFA structure works properly
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.getcwd())

try:
    print("🧪 Testing TIFA reorganized structure...")
    
    # Test core imports
    print("Testing core imports...")
    from src.core.config import Config
    from src.core.models import ThreatIntelItem
    from src.core.database import ThreatIntelDatabase
    from src.core.aggregator import ThreatIntelAggregator
    print("✅ Core imports successful")
    
    # Test collectors
    print("Testing collector imports...")
    from src.collectors.ioc_extractor import IOCExtractor
    from src.collectors.feed_collector import FeedCollector
    print("✅ Collector imports successful")
    
    # Test analyzers
    print("Testing analyzer imports...")
    from src.analyzers.ai_analyzer import AIAnalyzer
    print("✅ Analyzer imports successful")
    
    # Test basic functionality
    print("Testing basic initialization...")
    config = Config()
    print(f"✅ Config loaded with {len(config.THREAT_FEEDS)} feeds")
    
    db = ThreatIntelDatabase()
    print(f"✅ Database initialized at {db.db_path}")
    
    aggregator = ThreatIntelAggregator()
    print("✅ Aggregator initialized")
    
    print("\n🎉 All tests passed! TIFA reorganized structure is working properly.")
    print("✅ You can now run: streamlit run app.py")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print(f"❌ Failed to verify reorganized structure")
    import traceback
    traceback.print_exc()
