#!/usr/bin/env python3
"""
Threat Intelligence Feed Aggregator - Main Entry Point
A comprehensive cybersecurity threat intelligence platform
"""

import logging
from dashboard import ThreatIntelDashboard
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main entry point for the application"""
    try:
        logger.info("Starting Threat Intelligence Feed Aggregator...")
        
        # Create and launch dashboard
        dashboard = ThreatIntelDashboard()
        demo = dashboard.create_interface()
        
        logger.info(f"Launching web interface on {Config.SERVER_HOST}:{Config.SERVER_PORT}")
        
        # Launch the interface
        demo.launch(
            server_name=Config.SERVER_HOST,
            server_port=Config.SERVER_PORT,
            share=True,
            debug=False
        )
        
    except Exception as e:
        logger.error(f"Error starting application: {str(e)}")
        raise

if __name__ == "__main__":
    main()