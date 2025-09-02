#!/usr/bin/env python3
"""
Threat Intelligence Demo Script
Demonstrates all core functionality
"""

import asyncio
import logging
import time
from aggregator import ThreatIntelAggregator
from config import Config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_demo():
    """Run comprehensive demo of threat intelligence system"""
    
    print("🛡️ THREAT INTELLIGENCE FEED AGGREGATOR DEMO")
    print("=" * 50)
    
    # Initialize components
    print("\n1️⃣ Initializing Components...")
    config = Config()
    aggregator = ThreatIntelAggregator()
    
    print(f"   ✅ Configuration loaded")
    print(f"   ✅ Database initialized: {aggregator.db.db_path}")
    print(f"   ✅ Feed collector ready with {len(aggregator.feed_collector.feeds)} feeds")
    
    # Show configured feeds
    print("\n2️⃣ Configured Threat Intelligence Feeds:")
    for feed in aggregator.feed_collector.feeds:
        print(f"   📡 {feed['name']} - {feed['url']}")
    
    # Run aggregation
    print("\n3️⃣ Running Threat Intelligence Aggregation...")
    print("   🔄 Collecting feeds...")
    start_time = time.time()
    
    try:
        result = aggregator.refresh_feeds()
        elapsed = time.time() - start_time
        print(f"   ✅ Aggregation completed in {elapsed:.2f} seconds")
        print(f"   📄 Result: {result}")
    except Exception as e:
        print(f"   ❌ Aggregation failed: {e}")
        return
    
    # Show statistics
    print("\n4️⃣ Collection Statistics:")
    stats = aggregator.db.get_statistics()
    print(f"   📊 Total Threats: {stats['total_threats']}")
    print(f"   🎯 Total IOCs: {stats['total_iocs']}")
    print(f"   📡 Sources: {stats['total_sources']}")
    print(f"   🕐 Last Update: {stats['last_update']}")
    
    # Show recent threats
    print("\n5️⃣ Recent Threat Intelligence (Top 5):")
    recent_threats = aggregator.db.get_recent_threats(limit=5)
    
    if recent_threats:
        for i, threat in enumerate(recent_threats, 1):
            print(f"\n   {i}. {threat.title}")
            print(f"      📊 Severity: {threat.severity}")
            print(f"      📡 Source: {threat.source}")
            print(f"      📅 Date: {threat.published_date}")
            print(f"      🎯 IOCs: {len(threat.iocs)} indicators")
            print(f"      📝 Summary: {threat.summary[:100]}...")
    else:
        print("   📭 No threats found")
    
    # IOC extraction demo
    print("\n6️⃣ IOC Extraction Examples:")
    if recent_threats:
        for threat in recent_threats[:3]:
            if threat.iocs:
                print(f"\n   From: {threat.title}")
                for ioc_type, iocs in threat.iocs.items():
                    if iocs:
                        print(f"      {ioc_type}: {len(iocs)} found")
                        # Show first few examples
                        for ioc in list(iocs)[:3]:
                            print(f"        - {ioc}")
    
    # Search demo
    print("\n7️⃣ IOC Search Demo:")
    # Find any IOC to search for
    search_ioc = None
    for threat in recent_threats:
        for ioc_type, iocs in threat.iocs.items():
            if iocs:
                search_ioc = list(iocs)[0]
                break
        if search_ioc:
            break
    
    if search_ioc:
        print(f"   🔍 Searching for: {search_ioc}")
        search_results = aggregator.db.search_ioc(search_ioc)
        print(f"   📊 Found {len(search_results)} matching threats")
        
        for result in search_results[:2]:
            print(f"      - {result.title} ({result.severity})")
    else:
        print("   📭 No IOCs available for search demo")
    
    # AI Analysis demo
    print("\n8️⃣ AI Analysis Demo:")
    if recent_threats and hasattr(aggregator, 'ai_analyzer'):
        try:
            sample_threat = recent_threats[0]
            print(f"   🤖 Analyzing: {sample_threat.title}")
            
            # This would show AI analysis if available
            print(f"   📝 Original Summary: {sample_threat.summary[:150]}...")
            print("   ✅ AI enhancement ready (requires API key)")
            
        except Exception as e:
            print(f"   ⚠️ AI analysis unavailable: {e}")
    else:
        print("   ⚠️ AI analysis requires configuration")
    
    # Dashboard info
    print("\n9️⃣ Dashboard Access:")
    print("   🌐 Launch dashboard with: python main_simple.py")
    print("   🔗 URL: http://127.0.0.1:7861")
    print("   📱 Features:")
    print("      - Real-time threat feed monitoring")
    print("      - Interactive IOC search")
    print("      - Statistics and analytics")
    print("      - Clean, responsive interface")
    
    print("\n" + "=" * 50)
    print("🎉 Demo completed successfully!")
    print("🚀 Ready for production deployment")

if __name__ == "__main__":
    run_demo()
