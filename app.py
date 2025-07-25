#!/usr/bin/env python3
"""
Threat Intelligence Feed Aggregator - Hugging Face Spaces Deployment
A production-ready AI-powered threat intelligence platform
"""

import os
import sys
import logging
import gradio as gr
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add current directory to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import our modules
try:
    from dashboard import ThreatIntelDashboard
    from config import Config
    
    # Verify Gemini API keys are configured
    if not Config.GEMINI_API_KEYS or not any(Config.GEMINI_API_KEYS):
        logging.warning("⚠️ No Gemini API keys configured. Using fallback mode.")
    else:
        logging.info("✅ Gemini API keys configured successfully")
        
except ImportError as e:
    logging.error(f"Failed to import required modules: {e}")
    raise

def create_demo():
    """Create and configure the demo interface"""
    try:
        # Initialize dashboard
        dashboard = ThreatIntelDashboard()
        
        # Create interface
        demo = dashboard.create_interface()
        
        # Configure for production deployment
        demo.queue(default_concurrency_limit=10)
        
        return demo
        
    except Exception as e:
        logging.error(f"Failed to create demo: {e}")
        
        # Create fallback interface
        def error_interface():
            return "❌ Failed to initialize threat intelligence dashboard. Please check logs."
        
        return gr.Interface(
            fn=error_interface,
            inputs=[],
            outputs=gr.Textbox(label="Status"),
            title="⚠️ Threat Intelligence Aggregator - Error",
            description="System initialization failed. Please contact administrator."
        )

def main():
    """Main entry point for Hugging Face Spaces"""
    logging.info("🚀 Starting Threat Intelligence Feed Aggregator...")
    
    # Create demo interface
    demo = create_demo()
    
    # Launch configuration for Hugging Face Spaces
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        show_error=True,
        show_api=False,
        max_threads=10
    )

if __name__ == "__main__":
    main()
