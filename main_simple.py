#!/usr/bin/env python3
"""
Simple Threat Intelligence Feed Aggregator
Core functionality: monitoring, summarization, and analysis
"""

import asyncio
import logging
from simple_dashboard import SimpleThreatDashboard

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    """Main entry point for the threat intelligence dashboard"""
    print("🛡️ Starting Threat Intelligence Dashboard...")
    print("Features:")
    print("  ✅ Real-time threat feed monitoring")
    print("  ✅ AI-powered threat summarization") 
    print("  ✅ IOC extraction and search")
    print("  ✅ Simple, clean dashboard interface")
    print("  ✅ Automatic feed aggregation")
    print("\n🚀 Launching dashboard on http://127.0.0.1:7861")
    
    try:
        dashboard = SimpleThreatDashboard()
        dashboard.launch(share=False, port=7861)
    except Exception as e:
        print(f"❌ Error starting dashboard: {e}")
        print("Please check the logs for more details")

if __name__ == "__main__":
    main()
