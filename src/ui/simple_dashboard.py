#!/usr/bin/env python3
"""
Simple Threat Intelligence Dashboard
Focus on core functionality: monitoring, summarization, and analysis
"""

import gradio as gr
import logging
import asyncio
import json
from datetime import datetime
from typing import List, Dict, Any

# Import our modules
from aggregator import ThreatIntelAggregator
from config import Config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SimpleThreatDashboard:
    """Simple, clean threat intelligence dashboard focused on core functionality"""
    
    def __init__(self):
        """Initialize the dashboard with core components"""
        self.config = Config()
        self.aggregator = ThreatIntelAggregator()
        
    def get_threat_summary(self) -> str:
        """Get a clean summary of current threats"""
        try:
            threats = self.aggregator.db.get_recent_threats(limit=10)
            if not threats:
                return """
                <div style="background: #f0f9ff; padding: 20px; border-radius: 8px; text-align: center;">
                    <h3>🛡️ No threats found</h3>
                    <p>Click 'Refresh Feeds' to collect the latest threat intelligence</p>
                </div>
                """
            
            summary_html = """
            <div style="background: white; padding: 20px; border-radius: 8px; border: 1px solid #e5e7eb;">
                <h3 style="color: #1f2937; margin-bottom: 20px;">🔍 Latest Threat Intelligence</h3>
            """
            
            for threat in threats:
                severity_color = {
                    "High": "#ef4444",
                    "Medium": "#f59e0b", 
                    "Low": "#10b981"
                }.get(threat.severity, "#6b7280")
                
                summary_html += f"""
                <div style="background: #f9fafb; padding: 15px; margin-bottom: 15px; 
                           border-radius: 6px; border-left: 4px solid {severity_color};">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <strong style="color: #1f2937;">{threat.title}</strong>
                        <span style="background: {severity_color}; color: white; padding: 2px 8px; 
                                   border-radius: 12px; font-size: 12px;">{threat.severity}</span>
                    </div>
                    <p style="color: #6b7280; margin: 5px 0; font-size: 14px;">
                        Source: {threat.source} | Date: {threat.published_date}
                    </p>
                    <p style="color: #374151; margin: 0; line-height: 1.4;">
                        {threat.summary[:200]}{'...' if len(threat.summary) > 200 else ''}
                    </p>
                </div>
                """
            
            summary_html += "</div>"
            return summary_html
            
        except Exception as e:
            logger.error(f"Error getting threat summary: {e}")
            return f"""
            <div style="background: #fef2f2; padding: 20px; border-radius: 8px; color: #dc2626;">
                <strong>Error:</strong> {str(e)}
            </div>
            """
    
    def refresh_feeds(self) -> tuple[str, str]:
        """Refresh threat intelligence feeds"""
        try:
            # Show loading state
            status = """
            <div style="background: #dbeafe; padding: 15px; border-radius: 8px; text-align: center;">
                <strong>🔄 Refreshing threat intelligence feeds...</strong>
            </div>
            """
            
            # Run the aggregation
            result = self.aggregator.refresh_feeds()
            
            # Get updated summary
            summary = self.get_threat_summary()
            
            # Success status
            status = f"""
            <div style="background: #dcfce7; padding: 15px; border-radius: 8px; text-align: center;">
                <strong>✅ Feeds refreshed successfully!</strong><br>
                <small>{result}</small>
            </div>
            """
            
            return summary, status
            
        except Exception as e:
            logger.error(f"Error refreshing feeds: {e}")
            error_status = f"""
            <div style="background: #fef2f2; padding: 15px; border-radius: 8px; text-align: center; color: #dc2626;">
                <strong>❌ Error refreshing feeds:</strong> {str(e)}
            </div>
            """
            return self.get_threat_summary(), error_status
    
    def search_iocs(self, query: str) -> str:
        """Search for IOCs in the database"""
        if not query.strip():
            return """
            <div style="background: #f9fafb; padding: 20px; border-radius: 8px; text-align: center;">
                <p>Enter an IP address, domain, hash, or URL to search for IOCs</p>
            </div>
            """
        
        try:
            results = self.aggregator.db.search_ioc(query.strip())
            
            if not results:
                return f"""
                <div style="background: #fef3c7; padding: 20px; border-radius: 8px;">
                    <h4>🔍 IOC Search: {query}</h4>
                    <p>No matches found in the threat intelligence database</p>
                </div>
                """
            
            results_html = f"""
            <div style="background: white; padding: 20px; border-radius: 8px; border: 1px solid #e5e7eb;">
                <h4 style="color: #1f2937;">🔍 IOC Search Results: {query}</h4>
                <p style="color: #059669; font-weight: 600;">Found {len(results)} matches</p>
            """
            
            for threat in results[:5]:  # Show top 5 results
                severity_color = {
                    "High": "#ef4444",
                    "Medium": "#f59e0b", 
                    "Low": "#10b981"
                }.get(threat.severity, "#6b7280")
                
                results_html += f"""
                <div style="background: #f9fafb; padding: 15px; margin: 10px 0; 
                           border-radius: 6px; border-left: 4px solid {severity_color};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong>{threat.title}</strong>
                        <span style="background: {severity_color}; color: white; padding: 2px 8px; 
                                   border-radius: 12px; font-size: 12px;">{threat.severity}</span>
                    </div>
                    <p style="color: #6b7280; margin: 5px 0; font-size: 14px;">
                        {threat.source} | {threat.published_date}
                    </p>
                    <p style="color: #374151; margin: 0;">
                        {threat.summary[:150]}{'...' if len(threat.summary) > 150 else ''}
                    </p>
                </div>
                """
            
            if len(results) > 5:
                results_html += f"<p style='text-align: center; color: #6b7280;'>... and {len(results) - 5} more results</p>"
            
            results_html += "</div>"
            return results_html
            
        except Exception as e:
            logger.error(f"Error searching IOCs: {e}")
            return f"""
            <div style="background: #fef2f2; padding: 20px; border-radius: 8px; color: #dc2626;">
                <strong>Error searching IOCs:</strong> {str(e)}
            </div>
            """
    
    def get_statistics(self) -> str:
        """Get simple statistics about collected threats"""
        try:
            stats = self.aggregator.db.get_statistics()
            
            return f"""
            <div style="background: white; padding: 20px; border-radius: 8px; border: 1px solid #e5e7eb;">
                <h3 style="color: #1f2937; margin-bottom: 20px;">📊 Intelligence Statistics</h3>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
                    <div style="background: #dbeafe; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 24px; font-weight: bold; color: #1e40af;">{stats['total_threats']}</div>
                        <div style="color: #1f2937;">Total Threats</div>
                    </div>
                    
                    <div style="background: #dcfce7; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 24px; font-weight: bold; color: #059669;">{stats['total_iocs']}</div>
                        <div style="color: #1f2937;">Total IOCs</div>
                    </div>
                    
                    <div style="background: #fef3c7; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 24px; font-weight: bold; color: #d97706;">{stats['total_sources']}</div>
                        <div style="color: #1f2937;">Sources</div>
                    </div>
                </div>
                
                <div style="margin-top: 20px; padding: 15px; background: #f3f4f6; border-radius: 8px;">
                    <strong>Last Update:</strong> {stats['last_update']}
                </div>
            </div>
            """
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return f"""
            <div style="background: #fef2f2; padding: 20px; border-radius: 8px; color: #dc2626;">
                <strong>Error loading statistics:</strong> {str(e)}
            </div>
            """
    
    def launch(self, share: bool = False, port: int = 7860):
        """Launch the simple dashboard"""
        
        # Create the interface
        with gr.Blocks(
            title="🛡️ Threat Intelligence Dashboard",
            theme=gr.themes.Soft()
        ) as interface:
            
            # Header
            gr.HTML("""
            <div style="text-align: center; background: linear-gradient(135deg, #2563eb, #1d4ed8); 
                       padding: 30px; border-radius: 12px; margin-bottom: 30px; color: white;">
                <h1 style="margin: 0; font-size: 2.5em;">🛡️ Threat Intelligence Dashboard</h1>
                <p style="margin: 10px 0 0 0; font-size: 1.1em; opacity: 0.9;">
                    Simple, Effective Threat Monitoring & Analysis
                </p>
            </div>
            """)
            
            # Main tabs
            with gr.Tabs():
                
                # Live Feed Tab
                with gr.Tab("🔴 Live Feed"):
                    with gr.Row():
                        with gr.Column(scale=3):
                            threat_display = gr.HTML(
                                value=self.get_threat_summary(),
                                label="Current Threats"
                            )
                        
                        with gr.Column(scale=1):
                            gr.HTML("<h3>🎛️ Controls</h3>")
                            
                            refresh_btn = gr.Button(
                                "🔄 Refresh Feeds", 
                                variant="primary",
                                size="lg"
                            )
                            
                            status_display = gr.HTML(
                                value="""
                                <div style="background: #f3f4f6; padding: 15px; border-radius: 8px; text-align: center;">
                                    <strong>Ready</strong>
                                </div>
                                """,
                                label="Status"
                            )
                
                # Analytics Tab
                with gr.Tab("📊 Analytics"):
                    stats_display = gr.HTML(
                        value=self.get_statistics(),
                        label="Statistics"
                    )
                    
                    refresh_stats_btn = gr.Button("🔄 Refresh Statistics", variant="secondary")
                
                # IOC Search Tab
                with gr.Tab("🔍 IOC Search"):
                    with gr.Row():
                        with gr.Column():
                            gr.HTML("<h3>🔍 Search Indicators of Compromise (IOCs)</h3>")
                            
                            ioc_input = gr.Textbox(
                                label="Enter IOC",
                                placeholder="IP address, domain, hash, URL...",
                                lines=2
                            )
                            
                            search_btn = gr.Button("🔍 Search", variant="primary")
                        
                        with gr.Column():
                            ioc_results = gr.HTML(
                                value="""
                                <div style="background: #f9fafb; padding: 20px; border-radius: 8px; text-align: center;">
                                    <p>Enter an IOC to search the threat intelligence database</p>
                                </div>
                                """,
                                label="Search Results"
                            )
            
            # Event handlers
            refresh_btn.click(
                fn=self.refresh_feeds,
                outputs=[threat_display, status_display]
            )
            
            refresh_stats_btn.click(
                fn=self.get_statistics,
                outputs=stats_display
            )
            
            search_btn.click(
                fn=self.search_iocs,
                inputs=ioc_input,
                outputs=ioc_results
            )
            
            ioc_input.submit(
                fn=self.search_iocs,
                inputs=ioc_input,
                outputs=ioc_results
            )
        
        # Launch
        interface.launch(
            share=share,
            server_port=port,
            server_name="0.0.0.0" if share else "127.0.0.1",
            show_error=True
        )

if __name__ == "__main__":
    dashboard = SimpleThreatDashboard()
    dashboard.launch(share=False, port=7861)
