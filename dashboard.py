"""
Gradio web interface for the Threat Intelligence Aggregator
"""

import gradio as gr
import threading
import time
from typing import Tuple
import logging
from aggregator import ThreatIntelAggregator
from config import Config

logger = logging.getLogger(__name__)

class ThreatIntelDashboard:
    """Gradio web interface for the Threat Intelligence Aggregator"""
    
    def __init__(self):
        self.aggregator = ThreatIntelAggregator()
    
    def create_interface(self) -> gr.Blocks:
        """Create the Gradio web interface"""
        
        # Create a custom theme with professional colors
        custom_theme = gr.themes.Default(
            primary_hue="slate",
            secondary_hue="blue",
            neutral_hue="gray",
            font=gr.themes.GoogleFont("Inter"),
        ).set(
            body_background_fill="linear-gradient(135deg, #1e293b 0%, #334155 100%)",
            body_text_color="#f8fafc",
            block_background_fill="rgba(248, 250, 252, 0.98)",
            block_border_color="#e2e8f0",
            block_shadow="0 10px 25px rgba(0, 0, 0, 0.15)",
            button_primary_background_fill="linear-gradient(45deg, #3b82f6, #2563eb)",
            button_primary_text_color="#ffffff",
            input_background_fill="#ffffff",
            input_border_color="#d1d5db",
        )
        
        with gr.Blocks(title=Config.APP_TITLE, theme=custom_theme, css=self._get_custom_css()) as demo:
            gr.Markdown(f"# 🛡️ {Config.APP_TITLE}")
            gr.Markdown(f"**{Config.APP_DESCRIPTION}**")
            
            # Add welcome message with styling
            gr.HTML("""
            <div style="background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); 
                        padding: 25px; 
                        border-radius: 12px; 
                        text-align: center; 
                        margin: 20px 0;
                        box-shadow: 0 8px 20px rgba(30, 64, 175, 0.3);
                        border: 1px solid rgba(59, 130, 246, 0.2);">
                <h2 style="color: #ffffff; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); font-size: 24px;">
                    �️ Professional Threat Intelligence Platform
                </h2>
                <p style="color: #e0e7ff; margin: 10px 0 0 0; font-size: 14px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                    Real-time monitoring • AI-powered analysis • Enterprise-grade security
                </p>
            </div>
            """)
            
            with gr.Tabs():
                self._create_dashboard_tab()
                self._create_search_tab()
                self._create_ioc_export_tab()
                self._create_about_tab()
                self._create_monitoring_tab()
            
            # Start auto-refresh in background
            self._start_auto_refresh()
            
            return demo
    
    def _get_custom_css(self) -> str:
        """Get custom CSS for enhanced styling"""
        return """
        /* Professional styling with consistent color scheme */
        .gradio-container {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%) !important;
            min-height: 100vh;
        }
        
        .block {
            background: rgba(248, 250, 252, 0.98) !important;
            border-radius: 12px !important;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15) !important;
            border: 1px solid rgba(226, 232, 240, 0.3) !important;
        }
        
        .tab-nav {
            background: linear-gradient(135deg, #1e40af, #1d4ed8) !important;
            border-radius: 10px !important;
            padding: 5px !important;
        }
        
        .tab-nav button {
            color: #e0e7ff !important;
            font-weight: 600 !important;
            border-radius: 8px !important;
            transition: all 0.3s ease !important;
        }
        
        .tab-nav button:hover {
            background: rgba(224, 231, 255, 0.15) !important;
            transform: translateY(-1px) !important;
        }
        
        .tab-nav button.selected {
            background: #ffffff !important;
            color: #1e40af !important;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15) !important;
        }
        
        /* Professional button styling */
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #2563eb) !important;
            border: none !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            border-radius: 8px !important;
            padding: 10px 20px !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.25) !important;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 16px rgba(59, 130, 246, 0.35) !important;
        }
        
        /* Clean input field styling */
        input, textarea, select {
            border: 1px solid #d1d5db !important;
            border-radius: 8px !important;
            padding: 10px 12px !important;
            font-size: 14px !important;
            transition: all 0.3s ease !important;
        }
        
        input:focus, textarea:focus, select:focus {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
        }
        
        /* Dropdown styling */
        .dropdown {
            background: #ffffff !important;
            border: 1px solid #d1d5db !important;
            border-radius: 8px !important;
        }
        
        /* Professional text styling */
        .markdown-text {
            color: #1e293b !important;
            line-height: 1.6 !important;
        }
        
        h1, h2, h3, h4, h5, h6 {
            color: #1e293b !important;
        }
        
        /* Status and info cards */
        .status-info {
            background: linear-gradient(135deg, #374151, #1f2937) !important;
            color: #f9fafb !important;
            border-radius: 10px !important;
            padding: 16px !important;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .block {
                margin: 8px !important;
                padding: 12px !important;
            }
            
            .btn-primary {
                padding: 8px 16px !important;
                font-size: 14px !important;
            }
        }
        """
    
    def _create_dashboard_tab(self):
        """Create the dashboard tab"""
        with gr.TabItem("📊 Dashboard"):
            gr.HTML("""
            <div style="background: linear-gradient(135deg, #1e40af 0%, #1d4ed8 100%); 
                        padding: 20px; 
                        border-radius: 10px; 
                        text-align: center; 
                        margin-bottom: 20px;
                        box-shadow: 0 6px 16px rgba(30, 64, 175, 0.25);">
                <h2 style="color: #ffffff; margin: 0; font-size: 22px; text-shadow: 1px 1px 3px rgba(0,0,0,0.3);">
                    � Threat Intelligence Dashboard
                </h2>
                <p style="color: #dbeafe; margin: 8px 0 0 0; font-size: 14px;">
                    Monitor • Analyze • Respond
                </p>
            </div>
            """)
            
            # Add severity filter
            with gr.Row():
                severity_filter = gr.Dropdown(
                    choices=["All", "High", "Medium", "Low"],
                    label="🔍 Filter by Severity",
                    value="All",
                    scale=1
                )
                refresh_btn = gr.Button("🔄 Refresh Feeds", variant="primary", 
                                      elem_classes=["btn-primary"], scale=1)
                refresh_status = gr.Textbox(label="📊 Status", interactive=False, scale=2)
            
            dashboard_display = gr.HTML(self._get_threat_list())
            
            # Handle both refresh and filter
            refresh_btn.click(
                fn=self._refresh_feeds_handler,
                outputs=[refresh_status, dashboard_display]
            )
            
            severity_filter.change(
                fn=self._filter_by_severity,
                inputs=[severity_filter],
                outputs=[dashboard_display]
            )
    
    def _create_search_tab(self):
        """Create the search tab"""
        with gr.TabItem("🔍 Search"):
            gr.HTML("""
            <div style="background: linear-gradient(45deg, #fa709a, #fee140); 
                        padding: 25px; 
                        border-radius: 15px; 
                        text-align: center; 
                        margin-bottom: 25px;
                        box-shadow: 0 8px 16px rgba(250, 112, 154, 0.3);">
                <h2 style="color: #ffffff; margin: 0; font-size: 28px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                    🔎 Advanced Threat Search Engine 🔎
                </h2>
                <p style="color: #ffffff; margin: 10px 0 0 0; font-size: 16px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                    Search CVEs • Find IOCs • Track campaigns • Hunt threats
                </p>
            </div>
            """)
            
            with gr.Row():
                search_query = gr.Textbox(
                    label="🔍 Search Query", 
                    placeholder="Enter keywords, CVE IDs, domains, malware names, IOCs...",
                    scale=3
                )
                search_btn = gr.Button("🚀 Search", variant="primary", 
                                     elem_classes=["btn-primary"], scale=1)
            
            search_results = gr.HTML()
            
            search_btn.click(
                fn=self._search_threats,
                inputs=[search_query],
                outputs=[search_results]
            )
    
    def _create_ioc_export_tab(self):
        """Create the IOC export tab"""
        with gr.TabItem("📋 IOC Export"):
            gr.HTML("""
            <div style="background: linear-gradient(45deg, #a8edea, #fed6e3); 
                        padding: 25px; 
                        border-radius: 15px; 
                        text-align: center; 
                        margin-bottom: 25px;
                        box-shadow: 0 8px 16px rgba(168, 237, 234, 0.4);">
                <h2 style="color: #2d3748; margin: 0; font-size: 28px; text-shadow: 1px 1px 2px rgba(255,255,255,0.8);">
                    📋 IOC Export Center 📋
                </h2>
                <p style="color: #2d3748; margin: 10px 0 0 0; font-size: 16px; text-shadow: 1px 1px 2px rgba(255,255,255,0.6);">
                    Export indicators • SIEM integration • Threat hunting feeds
                </p>
            </div>
            """)
            
            with gr.Row():
                export_format = gr.Dropdown(
                    choices=["json", "csv"],
                    label="📄 Export Format",
                    value="json",
                    scale=2
                )
                export_btn = gr.Button("📥 Export IOCs", variant="primary", 
                                     elem_classes=["btn-primary"], scale=1)
            
            export_output = gr.Textbox(
                label="📊 Exported IOCs",
                lines=20,
                max_lines=30,
                placeholder="Your exported IOCs will appear here..."
            )
            
            export_btn.click(
                fn=self._export_iocs_handler,
                inputs=[export_format],
                outputs=[export_output]
            )
    
    def _create_about_tab(self):
        """Create the about tab"""
        with gr.TabItem("ℹ️ About"):
            gr.Markdown(self._get_about_content())
    
    def _create_monitoring_tab(self):
        """Create the AI monitoring tab"""
        with gr.TabItem("🔧 AI Monitor"):
            gr.Markdown("## 🤖 AI Performance & Capacity Monitoring")
            
            with gr.Row():
                refresh_stats_btn = gr.Button("🔄 Refresh Stats", variant="primary")
                
            stats_output = gr.HTML(value=self._get_ai_stats_html())
            
            refresh_stats_btn.click(
                fn=self._refresh_ai_stats,
                inputs=[],
                outputs=[stats_output]
            )
    
    def _refresh_feeds_handler(self) -> Tuple[str, str]:
        """Handle feed refresh"""
        status = self.aggregator.refresh_feeds()
        dashboard_html = self._get_threat_list()
        return status, dashboard_html
    
    def _filter_by_severity(self, severity: str) -> str:
        """Filter threats by severity level"""
        if severity == "All":
            data = self.aggregator.get_dashboard_data()
            threats = data['threats']
        else:
            threats = self.aggregator.get_threats_by_severity(severity)
        
        # Get stats for filtered view
        stats = {
            'total_threats': len(threats),
            'high_severity': len([t for t in threats if t.severity == "High"]),
            'medium_severity': len([t for t in threats if t.severity == "Medium"]),
            'low_severity': len([t for t in threats if t.severity == "Low"]),
            'total_iocs': sum(sum(len(iocs) for iocs in t.iocs.values()) for t in threats),
            'last_update': self.aggregator.last_update.strftime("%Y-%m-%d %H:%M:%S") if self.aggregator.last_update else "Never"
        }
        
        return self._format_filtered_threats(threats, stats, severity)
    
    def _get_threat_list(self) -> str:
        """Get formatted threat list for display"""
        data = self.aggregator.get_dashboard_data()
        threats = data['threats']
        stats = data['stats']
        
        # Create statistics display
        stats_html = self._create_stats_html(stats)
        
        # Create threat list
        threat_html = ""
        for threat in threats[:10]:  # Show top 10
            threat_html += self._format_threat_item(threat)
        
        return stats_html + threat_html
    
    def _format_filtered_threats(self, threats, stats, filter_type):
        """Format filtered threats for display"""
        # Create statistics display
        stats_html = self._create_stats_html(stats)
        
        if filter_type != "All":
            stats_html = f"""
            <div style="background: linear-gradient(135deg, #059669 0%, #047857 100%); 
                        padding: 20px; 
                        border-radius: 10px; 
                        text-align: center; 
                        margin: 20px 0;
                        box-shadow: 0 6px 16px rgba(5, 150, 105, 0.3);">
                <h3 style="color: #ffffff; margin: 0; font-size: 18px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                    🔍 Filtered by: {filter_type} Severity ({len(threats)} threats)
                </h3>
            </div>
            """ + stats_html
        
        # Create threat list
        threat_html = ""
        for threat in threats[:10]:  # Show top 10
            threat_html += self._format_threat_item(threat)
        
        if not threats:
            threat_html = f"""
            <div style="background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%); 
                        padding: 30px; 
                        border-radius: 12px; 
                        text-align: center;
                        box-shadow: 0 8px 20px rgba(107, 114, 128, 0.3);">
                <h3 style="color: #ffffff; margin: 0; font-size: 20px;">
                    📭 No {filter_type.lower()} severity threats found
                </h3>
                <p style="color: #d1d5db; margin: 10px 0 0 0;">
                    Try refreshing feeds or selecting a different filter
                </p>
            </div>
            """
        
        return stats_html + threat_html
    
    def _create_stats_html(self, stats: dict) -> str:
        """Create statistics HTML display"""
        return f"""
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 25px 0;">
            <div style="background: linear-gradient(135deg, #1e40af 0%, #1d4ed8 100%); 
                        padding: 25px; 
                        border-radius: 12px; 
                        text-align: center;
                        box-shadow: 0 8px 16px rgba(30, 64, 175, 0.25);
                        border: 1px solid rgba(59, 130, 246, 0.2);">
                <h3 style="margin: 0; color: #ffffff; font-size: 16px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                    🛡️ Total Threats
                </h3>
                <p style="font-size: 32px; font-weight: bold; margin: 10px 0; color: #ffffff; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                    {stats['total_threats']}
                </p>
            </div>
            <div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); 
                        padding: 25px; 
                        border-radius: 12px; 
                        text-align: center;
                        box-shadow: 0 8px 16px rgba(220, 38, 38, 0.25);
                        border: 1px solid rgba(239, 68, 68, 0.2);">
                <h3 style="margin: 0; color: #ffffff; font-size: 16px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                    🚨 High Severity
                </h3>
                <p style="font-size: 32px; font-weight: bold; margin: 10px 0; color: #ffffff; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                    {stats['high_severity']}
                </p>
            </div>
            <div style="background: linear-gradient(135deg, #ea580c 0%, #dc2626 100%); 
                        padding: 25px; 
                        border-radius: 12px; 
                        text-align: center;
                        box-shadow: 0 8px 16px rgba(234, 88, 12, 0.25);
                        border: 1px solid rgba(251, 146, 60, 0.2);">
                <h3 style="margin: 0; color: #ffffff; font-size: 16px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                    ⚠️ Medium Severity
                </h3>
                <p style="font-size: 32px; font-weight: bold; margin: 10px 0; color: #ffffff; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                    {stats['medium_severity']}
                </p>
            </div>
            <div style="background: linear-gradient(135deg, #059669 0%, #047857 100%); 
                        padding: 25px; 
                        border-radius: 12px; 
                        text-align: center;
                        box-shadow: 0 8px 16px rgba(5, 150, 105, 0.25);
                        border: 1px solid rgba(34, 197, 94, 0.2);">
                <h3 style="margin: 0; color: #ffffff; font-size: 16px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                    📊 Total IOCs
                </h3>
                <p style="font-size: 32px; font-weight: bold; margin: 10px 0; color: #ffffff; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                    {stats['total_iocs']}
                </p>
            </div>
        </div>
        <div style="background: linear-gradient(135deg, #374151 0%, #1f2937 100%); 
                    padding: 20px; 
                    border-radius: 10px; 
                    margin: 20px 0;
                    box-shadow: 0 6px 12px rgba(55, 65, 81, 0.3);
                    border: 1px solid rgba(75, 85, 99, 0.2);">
            <p style="margin: 0; color: #ffffff; font-size: 16px; font-weight: 600; text-align: center; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                🕒 Last Update: {stats['last_update']}
            </p>
        </div>
        """
    
    def _format_threat_item(self, threat) -> str:
        """Format a single threat item for display"""
        severity_colors = {
            "High": "linear-gradient(135deg, #dc2626, #b91c1c)",
            "Medium": "linear-gradient(135deg, #ea580c, #dc2626)", 
            "Low": "linear-gradient(135deg, #059669, #047857)"
        }
        
        severity_color = severity_colors.get(threat.severity, "linear-gradient(135deg, #6b7280, #4b5563)")
        
        ioc_summary = ", ".join([f"{k.replace('_', ' ').title()}: {len(v)}" for k, v in threat.iocs.items() if v])
        summary_formatted = threat.summary.replace('\n', '<br>')
        
        # Create severity badge with enhanced styling
        severity_badge = f"""
        <span style="background: {severity_color}; 
                     color: #ffffff; 
                     padding: 8px 16px; 
                     border-radius: 20px; 
                     font-size: 12px; 
                     font-weight: 700; 
                     margin-right: 15px;
                     text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
                     box-shadow: 0 4px 8px rgba(0,0,0,0.2);
                     display: inline-block;">
            {threat.severity.upper()}
        </span>
        """
        
        return f"""
        <div style="background: linear-gradient(135deg, #ffffff, #f8fafc); 
                    border: none; 
                    margin: 20px 0; 
                    padding: 25px; 
                    border-radius: 12px; 
                    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
                    border-left: 4px solid #3b82f6;
                    transition: all 0.3s ease;
                    position: relative;
                    overflow: hidden;">
            
            <!-- Subtle background pattern -->
            <div style="position: absolute; top: -30px; right: -30px; 
                        width: 60px; height: 60px; 
                        background: linear-gradient(45deg, rgba(59, 130, 246, 0.05), rgba(29, 78, 216, 0.05));
                        border-radius: 50%;
                        z-index: 0;"></div>
            
            <div style="position: relative; z-index: 1;">
                <h4 style="margin: 0 0 15px 0; color: #1e293b; font-size: 18px; line-height: 1.4;">
                    {severity_badge}
                    <span style="color: #1e293b; font-weight: 600;">{threat.title}</span>
                </h4>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 15px 0;">
                    <div style="background: rgba(59, 130, 246, 0.08); padding: 12px; border-radius: 8px; border: 1px solid rgba(59, 130, 246, 0.1);">
                        <strong style="color: #1e40af;">📰 Source:</strong> 
                        <span style="color: #334155; font-weight: 500;">{threat.source}</span>
                    </div>
                    <div style="background: rgba(107, 114, 128, 0.08); padding: 12px; border-radius: 8px; border: 1px solid rgba(107, 114, 128, 0.1);">
                        <strong style="color: #374151;">📅 Published:</strong> 
                        <span style="color: #334155; font-weight: 500;">{threat.published}</span>
                    </div>
                </div>
                
                <div style="background: rgba(248, 250, 252, 0.8); 
                            padding: 18px; 
                            border-radius: 10px; 
                            margin: 18px 0;
                            border: 1px solid rgba(226, 232, 240, 0.5);">
                    <p style="margin: 0; color: #475569; line-height: 1.6; font-size: 14px;">
                        {threat.description}
                    </p>
                </div>
                
                {f'''<div style="background: rgba(59, 130, 246, 0.08); 
                                padding: 14px; 
                                border-radius: 8px; 
                                margin: 14px 0;
                                border: 1px solid rgba(59, 130, 246, 0.15);">
                        <strong style="color: #1e40af;">🔍 IOCs Detected:</strong> 
                        <span style="color: #334155; font-weight: 500;">{ioc_summary}</span>
                    </div>''' if ioc_summary else ''}
                
                <div style="background: linear-gradient(135deg, #1e40af, #1d4ed8); 
                            color: #ffffff; 
                            padding: 18px; 
                            border-radius: 10px; 
                            margin: 18px 0;
                            box-shadow: 0 4px 12px rgba(30, 64, 175, 0.25);">
                    <strong style="color: #ffffff; display: block; margin-bottom: 8px; font-size: 14px;">
                        🤖 AI Analysis Summary:
                    </strong>
                    <div style="color: #e0e7ff; line-height: 1.5; font-size: 13px;">
                        {summary_formatted}
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 18px;">
                    <a href="{threat.link}" target="_blank" 
                       style="background: linear-gradient(135deg, #3b82f6, #2563eb); 
                              color: #ffffff; 
                              text-decoration: none; 
                              padding: 10px 20px; 
                              border-radius: 20px; 
                              font-weight: 600;
                              font-size: 13px;
                              box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
                              transition: all 0.3s ease;
                              display: inline-block;">
                        🔗 View Full Article
                    </a>
                </div>
            </div>
        </div>
        """
    
    def _search_threats(self, query: str) -> str:
        """Search threats and return formatted results"""
        if not query.strip():
            return """
            <div style="background: linear-gradient(45deg, #ffeaa7, #fdcb6e); 
                        padding: 30px; 
                        border-radius: 15px; 
                        text-align: center;
                        box-shadow: 0 8px 16px rgba(255, 234, 167, 0.4);">
                <h3 style="color: #2d3748; margin: 0; font-size: 24px;">
                    🔍 Please enter a search query
                </h3>
                <p style="color: #4a5568; margin: 10px 0 0 0; font-size: 16px;">
                    Try searching for CVE IDs, malware names, domains, or threat keywords
                </p>
            </div>
            """
        
        results = self.aggregator.search_threats(query)
        
        if not results:
            return f"""
            <div style="background: linear-gradient(45deg, #fab1a0, #e17055); 
                        padding: 30px; 
                        border-radius: 15px; 
                        text-align: center;
                        box-shadow: 0 8px 16px rgba(250, 177, 160, 0.4);">
                <h3 style="color: #ffffff; margin: 0; font-size: 24px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                    🚫 No threats found matching '{query}'
                </h3>
                <p style="color: #ffffff; margin: 10px 0 0 0; font-size: 16px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                    Try different keywords or check your spelling
                </p>
            </div>
            """
        
        search_html = f"""
        <div style="background: linear-gradient(45deg, #00cec9, #55a3ff); 
                    padding: 25px; 
                    border-radius: 15px; 
                    text-align: center; 
                    margin-bottom: 25px;
                    box-shadow: 0 8px 16px rgba(0, 206, 201, 0.3);">
            <h3 style="color: #ffffff; margin: 0; font-size: 24px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                🎯 Search Results for '{query}' 
            </h3>
            <p style="color: #ffffff; margin: 10px 0 0 0; font-size: 16px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                Found {len(results)} matching threats
            </p>
        </div>
        """
        
        for threat in results[:10]:  # Show top 10 results
            search_html += self._format_threat_item(threat)
        
        return search_html
    
    def _export_iocs_handler(self, format_type: str) -> str:
        """Handle IOC export"""
        return self.aggregator.export_iocs(format_type)
    
    def _start_auto_refresh(self):
        """Start auto-refresh in background"""
        def auto_refresh():
            while True:
                time.sleep(Config.AUTO_REFRESH_INTERVAL)
                try:
                    # This would update the dashboard if we had state management
                    # For now, users need to manually refresh
                    pass
                except Exception as e:
                    logger.error(f"Auto-refresh error: {str(e)}")
        
        refresh_thread = threading.Thread(target=auto_refresh, daemon=True)
        refresh_thread.start()
    
    def _get_about_content(self) -> str:
        """Get about page content"""
        return """
        ## About This Tool
        
        The Threat Intelligence Feed Aggregator is an AI-powered platform designed to help security professionals:
        
        - **Aggregate** threat intelligence from multiple RSS/Atom feeds
        - **Extract** Indicators of Compromise (IOCs) automatically
        - **Analyze** threats using AI-powered summarization
        - **Search** through collected threat data
        - **Export** IOCs in multiple formats
        
        ### Features
        
        - 🔄 **Real-time Feed Collection**: Automatically fetches from curated security feeds
        - 🤖 **AI-Powered Analysis**: Generates summaries and assesses threat severity
        - 🔍 **Advanced Search**: Search across titles, descriptions, and summaries
        - 📊 **IOC Extraction**: Automatically extracts IPs, domains, hashes, CVEs, and more
        - 📋 **Export Capabilities**: Export IOCs in JSON or CSV format
        - 🛡️ **Security Focused**: Built specifically for cybersecurity professionals
        
        ### Data Sources
        
        - US-CERT CISA Advisories
        - SANS Internet Storm Center
        - Krebs on Security
        - Malware Bytes Labs
        - Threat Post
        
        ### Technical Stack
        
        - **Backend**: Python with SQLite database
        - **IOC Extraction**: Advanced regex pattern matching
        - **AI Analysis**: Mock implementation (ready for Ollama integration)
        - **Web Interface**: Gradio for intuitive user experience
        - **Data Processing**: Multi-threaded feed collection
        
        ### Usage Instructions
        
        1. **Dashboard**: View real-time threat intelligence and statistics
        2. **Refresh Feeds**: Click "Refresh Feeds" to update threat data
        3. **Search**: Use the search tab to find specific threats
        4. **Export**: Download IOCs in JSON or CSV format for integration
        
        ### Integration Ready
        
        This tool is designed to integrate with:
        - SIEM platforms
        - Security orchestration tools
        - Threat hunting workflows
        - Incident response playbooks
        
        ---
        
        **Built for the Cybersecurity Community** 🔒
        """
    
    def _refresh_ai_stats(self) -> str:
        """Refresh AI statistics"""
        return self._get_ai_stats_html()
    
    def _get_ai_stats_html(self) -> str:
        """Get AI statistics as HTML"""
        try:
            stats = self.aggregator.ai_analyzer.get_ai_stats()
            
            if not stats or stats.get("using_mock", False):
                return """
                <div style="background: #fef3c7; padding: 20px; border-radius: 10px; border-left: 4px solid #f59e0b;">
                    <h3 style="color: #92400e; margin: 0;">⚠️ AI Analysis in Fallback Mode</h3>
                    <p style="color: #78350f; margin: 10px 0 0 0;">AI analysis is currently using fallback mode. Check API configuration.</p>
                </div>
                """
            
            capacity = stats.get("capacity_analysis", {})
            total_rpm = capacity.get("total_theoretical_rpm", 0)
            available_rpm = capacity.get("available_rpm", 0)
            utilization = capacity.get("utilization_percentage", 0)
            
            html = f"""
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                
                <!-- Capacity Overview -->
                <div style="background: linear-gradient(135deg, #1e40af, #3730a3); color: white; padding: 20px; border-radius: 12px; text-align: center;">
                    <h3 style="margin: 0; color: white;">🚀 API Capacity</h3>
                    <div style="font-size: 28px; font-weight: bold; margin: 10px 0;">{available_rpm}/{total_rpm} RPM</div>
                    <div style="font-size: 14px; opacity: 0.9;">Available/Total Requests per Minute</div>
                    <div style="margin-top: 10px; font-size: 16px;">Utilization: {utilization}%</div>
                </div>
                
                <!-- Current Status -->
                <div style="background: linear-gradient(135deg, #059669, #047857); color: white; padding: 20px; border-radius: 12px; text-align: center;">
                    <h3 style="margin: 0; color: white;">📊 Current Status</h3>
                    <div style="margin: 10px 0;">
                        <div>Available Keys: {stats.get('available_keys', 0)}/2</div>
                        <div>Rate Limited: {stats.get('rate_limited_keys', 0)}</div>
                        <div>Active Model: {stats.get('current_model_index', 0) + 1}/4</div>
                    </div>
                </div>
            </div>
            
            <div style="margin: 20px 0;">
                <h3 style="color: #1e293b;">🔑 API Key Status</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
            """
            
            for key_info in stats.get("api_keys", []):
                status_color = "#ef4444" if key_info["is_rate_limited"] else "#22c55e"
                status_text = "Rate Limited" if key_info["is_rate_limited"] else "Available"
                
                html += f"""
                <div style="background: white; border: 2px solid {status_color}; padding: 15px; border-radius: 8px;">
                    <div style="font-weight: bold;">Key {key_info['index'] + 1}</div>
                    <div style="color: {status_color};">Status: {status_text}</div>
                    <div style="font-size: 12px; color: #6b7280;">
                        Daily: {key_info['daily_requests']}<br>
                        Total: {key_info['requests_made']}<br>
                        Last: {key_info['last_request'] or 'Never'}
                    </div>
                </div>
                """
            
            html += """
                </div>
            </div>
            
            <div>
                <h3 style="color: #1e293b;">🤖 Model Performance</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px;">
            """
            
            for model_info in stats.get("models", []):
                success_color = "#22c55e" if model_info["success_rate"] > 80 else "#f59e0b" if model_info["success_rate"] > 50 else "#ef4444"
                
                html += f"""
                <div style="background: white; border: 1px solid #e5e7eb; padding: 15px; border-radius: 8px;">
                    <div style="font-weight: bold; margin-bottom: 8px;">{model_info['name']}</div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span>Success Rate:</span>
                        <span style="color: {success_color}; font-weight: bold;">{model_info['success_rate']}%</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span>Requests:</span>
                        <span>{model_info['requests_made']}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span>Avg Time:</span>
                        <span>{model_info['avg_response_time']}s</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span>Capacity:</span>
                        <span>{model_info['theoretical_rpm']} RPM</span>
                    </div>
                    <div style="font-size: 12px; color: #6b7280;">
                        Last Used: {model_info['last_used'] or 'Never'}
                    </div>
                </div>
                """
            
            html += "</div></div>"
            return html
            
        except Exception as e:
            return f"""
            <div style="background: #fef2f2; padding: 20px; border-radius: 10px; border-left: 4px solid #ef4444;">
                <h3 style="color: #dc2626; margin: 0;">❌ Error Getting AI Stats</h3>
                <p style="color: #991b1b; margin: 10px 0 0 0;">Error: {str(e)}</p>
            </div>
            """
