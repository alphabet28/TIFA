"""
🛡️ ULTIMATE Threat Intelligence Command Center
Advanced Real-time Cybersecurity Platform with AI-Powered Analytics
Hackathon Challenge: Next-Generation Security Operations Center
"""

import gradio as gr
import asyncio
import threading
import time
import json
from typing import Tuple, Generator, List, Dict
import logging
from datetime import datetime
from aggregator import ThreatIntelAggregator
from config import Config

# Import advanced modules for cutting-edge features
try:
    from threat_visualization import ThreatVisualization
    from threat_chat import ThreatIntelligenceChat
    from threat_hunter import AutomatedThreatHunter
    from alert_system import LiveAlertSystem, AlertType, AlertSeverity
    ADVANCED_FEATURES_AVAILABLE = True
    logging.info("🚀 Advanced features loaded successfully!")
except ImportError as e:
    logging.warning(f"⚠️ Advanced features not available: {e}")
    ADVANCED_FEATURES_AVAILABLE = False

logger = logging.getLogger(__name__)

class RealTimeThreatDashboard:
    """Real-time streaming threat intelligence dashboard for SOC teams"""
    
    def __init__(self, aggregator=None):
        """Initialize Ultimate Threat Intelligence Command Center
        
        Args:
            aggregator: ThreatIntelAggregator instance for processing feeds
        """
        self.aggregator = aggregator or ThreatIntelAggregator()
        self.processing_active = False
        self.progress_data = {"current": 0, "total": 0, "status": "Ready"}
        self.logger = logging.getLogger(__name__)
        
        # Initialize advanced components if available
        if ADVANCED_FEATURES_AVAILABLE:
            self.visualization = ThreatVisualization()
            self.chat_assistant = ThreatIntelligenceChat(self.aggregator.ai_analyzer)
            self.threat_hunter = AutomatedThreatHunter(self.aggregator.db, self.aggregator.ai_analyzer)
            self.alert_system = LiveAlertSystem()
            
            # Start alert system
            self.alert_system.start_alert_system()
            
            # Add threat monitoring notification handler
            self.alert_system.add_notification_handler(self._handle_alert_notification)
            
            self.logger.info("🚀 Ultimate Threat Intelligence Command Center initialized with advanced features!")
        else:
            self.visualization = None
            self.chat_assistant = None
            self.threat_hunter = None
            self.alert_system = None
            self.logger.info("⚠️ Basic Threat Intelligence Dashboard initialized")
        
        self.logger.info("Real-time Threat Intelligence Dashboard initialized")
        
    def _handle_alert_notification(self, alert: Dict):
        """Handle alert notifications for dashboard updates"""
        try:
            self.logger.info(f"🚨 Alert triggered: {alert.get('severity', 'unknown').upper()} - {alert.get('message', 'Unknown')}")
        except Exception as e:
            self.logger.error(f"Error handling alert notification: {e}")
        
    def _create_header(self):
        """Create professional dashboard header"""
        return gr.HTML("""
        <div style="background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%); 
                   padding: 30px; border-radius: 15px; margin-bottom: 30px; color: white; text-align: center;
                   box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
            <h1 style="margin: 0; font-size: 2.5em; font-weight: 700; text-shadow: 2px 2px 4px rgba(0,0,0,0.5);">
                🛡️ Threat Intelligence Command Center
            </h1>
            <p style="margin: 15px 0 5px 0; font-size: 1.2em; color: #cbd5e1;">
                Real-time AI-powered cybersecurity threat intelligence aggregation and analysis
            </p>
            <div style="margin-top: 20px; display: flex; justify-content: center; gap: 30px; flex-wrap: wrap;">
                <div style="background: rgba(59, 130, 246, 0.2); padding: 10px 20px; border-radius: 25px;">
                    <span style="color: #60a5fa;">🤖 AI-Powered Analysis</span>
                </div>
                <div style="background: rgba(34, 197, 94, 0.2); padding: 10px 20px; border-radius: 25px;">
                    <span style="color: #4ade80;">⚡ Real-time Processing</span>
                </div>
                <div style="background: rgba(236, 72, 153, 0.2); padding: 10px 20px; border-radius: 25px;">
                    <span style="color: #f472b6;">🔍 Multi-source Intelligence</span>
                </div>
            </div>
        </div>
        """)
        
    def create_interface(self) -> gr.Blocks:
        """Create the advanced hackathon-ready interface"""
        
        # Professional cybersecurity theme
        custom_theme = gr.themes.Soft(
            primary_hue="blue",
            secondary_hue="slate", 
            neutral_hue="slate",
            font=gr.themes.GoogleFont("Source Sans Pro")
        ).set(
            body_background_fill="linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%)",
            body_text_color="#f1f5f9",
            block_background_fill="rgba(248, 250, 252, 0.95)",
            block_border_color="rgba(71, 85, 105, 0.3)",
            block_shadow="0 20px 40px rgba(0, 0, 0, 0.3)",
            button_primary_background_fill="linear-gradient(135deg, #2563eb, #1d4ed8)",
            button_primary_text_color="#ffffff"
        )
        
        with gr.Blocks(
            title="🛡️ Threat Intelligence SOC Dashboard - Young Graduates Hiring Program", 
            theme=custom_theme, 
            css=self._get_professional_css()
        ) as demo:
            
            # Header with hackathon branding
            self._create_header()
            
            with gr.Tabs() as tabs:
                # Real-time Threat Feed Tab
                with gr.Tab("🎯 Live Threat Feed", id="live_feed"):
                    self._create_live_feed_tab()
                
                # SOC Analytics Tab  
                with gr.Tab("📊 SOC Analytics", id="analytics"):
                    self._create_analytics_tab()
                
                # Threat Hunt Tab
                with gr.Tab("🔍 Threat Hunt", id="hunt"):
                    self._create_threat_hunt_tab()
                
                # IOC Intelligence Tab
                with gr.Tab("⚡ IOC Intelligence", id="ioc"):
                    self._create_ioc_tab()
                
                # AI Analysis Center
                with gr.Tab("🤖 AI Analysis Center", id="ai"):
                    self._create_ai_analysis_tab()
                
                # About Challenge
                with gr.Tab("🏆 Challenge Info", id="about"):
                    self._create_challenge_info_tab()
            
            return demo
            gr.Markdown(f"# 🛡️ {Config.APP_TITLE}")
            gr.Markdown(f"**{Config.APP_DESCRIPTION}**")
            gr.HTML("""
            <div style="background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); 
                        padding: 25px; 
                        border-radius: 12px; 
                        text-align: center; 
                        margin: 20px 0;
                        box-shadow: 0 8px 20px rgba(30, 64, 175, 0.3);
                        border: 1px solid rgba(59, 130, 246, 0.2);">
                <h2 style="color: #ffffff; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); font-size: 24px;">
                    ️ Professional Threat Intelligence Platform
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
            self._start_auto_refresh()
            return demo
    
    def _get_custom_css(self) -> str:
        """Get custom CSS for enhanced, modern, live styling with animated background"""
        return """
        /* Animated aurora/smoke background */
        .gradio-container {
            min-height: 100vh;
            font-family: 'Inter', 'Segoe UI', Arial, sans-serif !important;
            background: linear-gradient(270deg, #232946, #43435c, #232946, #2563eb, #22d3ee, #232946);
            background-size: 400% 400%;
            animation: auroraMove 18s ease-in-out infinite;
            position: relative;
        }
        @keyframes auroraMove {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        /* Subtle smoke/texture overlay */
        .gradio-container:before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            pointer-events: none;
            background: url('https://www.transparenttextures.com/patterns/smoke.png') repeat;
            opacity: 0.18;
            z-index: 0;
        }
        /* Ensure content is above overlay */
        .gradio-container > * {
            position: relative;
            z-index: 1;
        }
        /* Card style for stats */
        .stat-card {
            background: linear-gradient(120deg, #1e293b 60%, #334155 100%);
            color: #f8fafc;
            border-radius: 16px;
            box-shadow: 0 4px 16px rgba(30, 41, 59, 0.18);
            padding: 18px 20px 14px 20px;
            margin: 8px 0;
            display: flex;
            align-items: center;
            gap: 16px;
            transition: box-shadow 0.2s, transform 0.2s;
        }
        .stat-card:hover {
            box-shadow: 0 8px 32px rgba(59, 130, 246, 0.18);
            transform: translateY(-2px) scale(1.02);
        }
        .stat-icon {
            font-size: 2.2rem;
            margin-right: 10px;
            filter: drop-shadow(0 2px 6px rgba(30,64,175,0.12));
        }
        /* Live indicator */
        .live-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #22d3ee;
            margin-right: 8px;
            box-shadow: 0 0 8px #22d3ee99;
            animation: livepulse 1.2s infinite;
        }
        @keyframes livepulse {
            0% { box-shadow: 0 0 0 0 #22d3ee99; }
            70% { box-shadow: 0 0 0 8px #22d3ee11; }
            100% { box-shadow: 0 0 0 0 #22d3ee99; }
        }
        /* Tab bar improvements */
        .tab-nav {
            background: #232946 !important;
            border-radius: 8px !important;
            padding: 2px 8px !important;
            margin-bottom: 8px !important;
        }
        .tab-nav button {
            color: #e0e7ff !important;
            font-weight: 600 !important;
            border-radius: 8px !important;
            transition: background 0.2s, color 0.2s;
            padding: 6px 18px !important;
            font-size: 1rem !important;
        }
        .tab-nav button.selected {
            background: #22d3ee !important;
            color: #232946 !important;
            box-shadow: 0 2px 8px #22d3ee33 !important;
        }
        /* Button improvements */
        .btn-primary {
            background: linear-gradient(90deg, #22d3ee, #2563eb) !important;
            color: #fff !important;
            font-weight: 700 !important;
            border-radius: 8px !important;
            padding: 10px 24px !important;
            font-size: 1rem !important;
            box-shadow: 0 2px 8px #22d3ee33 !important;
            transition: box-shadow 0.2s, transform 0.2s;
        }
        .btn-primary:hover {
            box-shadow: 0 4px 16px #2563eb33 !important;
            transform: translateY(-1px) scale(1.03);
        }
        /* Loading spinner */
        .spinner {
            display: inline-block;
            width: 22px;
            height: 22px;
            border: 3px solid #22d3ee;
            border-top: 3px solid #2563eb;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-left: 10px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        /* Inputs and dropdowns */
        input, textarea, select {
            border: 1px solid #d1d5db !important;
            border-radius: 8px !important;
            padding: 10px 12px !important;
            font-size: 15px !important;
            background: #f8fafc !important;
            color: #232946 !important;
        }
        input:focus, textarea:focus, select:focus {
            border-color: #22d3ee !important;
            box-shadow: 0 0 0 2px #22d3ee33 !important;
        }
        /* Responsive tweaks */
        @media (max-width: 768px) {
            .block, .stat-card {
                margin: 6px !important;
                padding: 10px !important;
            }
            .btn-primary {
                padding: 8px 12px !important;
                font-size: 0.95rem !important;
            }
        }
        """
    
    def _create_dashboard_tab(self):
        """Create the dashboard tab with modern, live UI and centered refresh button"""
        with gr.TabItem("📊 Dashboard"):
            gr.HTML("""
            <div style='display: flex; align-items: center; justify-content: center; margin-bottom: 10px;'>
                <span class='live-dot'></span>
                <span style='color: #22d3ee; font-weight: 700; font-size: 1.1rem; letter-spacing: 1px;'>Live Dashboard</span>
            </div>
            <div style="background: linear-gradient(135deg, #232946 0%, #334155 100%); 
                        padding: 12px; 
                        border-radius: 10px; 
                        text-align: center; 
                        margin-bottom: 10px;
                        box-shadow: 0 4px 12px rgba(30, 64, 175, 0.18);">
                <h2 style="color: #ffffff; margin: 0; font-size: 22px; text-shadow: 1px 1px 3px rgba(0,0,0,0.3);">
                    🛡️ Threat Intelligence Dashboard
                </h2>
                <p style="color: #dbeafe; margin: 8px 0 0 0; font-size: 14px;">
                    Monitor • Analyze • Respond
                </p>
            </div>
            """)
            # Centered refresh button
            gr.HTML("""
            <div style='display: flex; justify-content: center; margin-bottom: 18px;'>
                <button id='center-refresh-btn' class='btn-primary' style='font-size: 1.1rem; padding: 12px 36px; display: flex; align-items: center; gap: 10px;'>
                    🔄 Refresh Feeds
                </button>
            </div>
            """)
            with gr.Row():
                severity_filter = gr.Dropdown(
                    choices=["All", "High", "Medium", "Low"],
                    label="🔍 Filter by Severity",
                    value="All",
                    scale=1
                )
                refresh_status = gr.Textbox(label="📊 Status", interactive=False, scale=2)
            dashboard_display = gr.HTML(self._get_threat_list())
            # JS to trigger Gradio refresh on custom button
            gr.HTML("""
            <script>
            document.addEventListener('DOMContentLoaded', function() {
                const btn = document.getElementById('center-refresh-btn');
                if(btn) {
                    btn.onclick = function() {
                        // Simulate click on the hidden Gradio refresh button
                        const gradioBtn = document.querySelector('button:contains("Refresh Feeds")');
                        if(gradioBtn) gradioBtn.click();
                    };
                }
            });
            </script>
            """)
            # Hidden Gradio refresh button for backend logic
            refresh_btn = gr.Button("Refresh Feeds", visible=False)
            def refresh_with_spinner():
                return ("Refreshing... <span class='spinner'></span>", *self._refresh_feeds_handler())
            refresh_btn.click(
                fn=refresh_with_spinner,
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
    
    def _refresh_feeds(self):
        """Enhanced feed refresh with comprehensive intelligence collection"""
        try:
            logger.info("🚀 Starting enhanced threat intelligence collection...")
            
            # Initialize progress tracking
            progress_steps = [
                "🔍 Scanning feed sources...",
                "📡 Collecting threat data...", 
                "🧠 AI analysis in progress...",
                "🔗 Extracting IOCs...",
                "💾 Storing intelligence...",
                "📊 Generating insights...",
                "✅ Collection complete!"
            ]
            
            current_progress = 0
            step_increment = 100 / len(progress_steps)
            
            # Step 1: Scan sources
            current_progress += step_increment
            
            # Get feed sources from config
            feed_sources = Config.RSS_FEEDS
            total_sources = len(feed_sources)
            
            # Step 2: Collect data
            current_progress += step_increment
            
            # Trigger aggregator refresh
            new_threats = self.aggregator.refresh_feeds()
            
            # Step 3: AI Analysis
            current_progress += step_increment
            
            # Step 4: IOC Extraction
            current_progress += step_increment
            total_iocs_extracted = 0
            for threat in new_threats:
                if hasattr(threat, 'iocs') and threat.iocs:
                    for ioc_type, ioc_list in threat.iocs.items():
                        total_iocs_extracted += len(ioc_list)
            
            # Step 5: Storage
            current_progress += step_increment
            
            # Step 6: Generate insights
            current_progress += step_increment
            recent_threats = self.aggregator.db.get_recent_threats(limit=20)
            ioc_stats = self.aggregator.db.get_ioc_statistics()
            
            # Step 7: Complete
            current_progress = 100
            final_progress_html = self._create_completion_progress_html(
                len(new_threats), 
                total_iocs_extracted, 
                len(recent_threats)
            )
            
            # Create enhanced threat display
            enhanced_display = self._create_enhanced_threat_display(recent_threats, new_threats, ioc_stats)
            
            return enhanced_display, final_progress_html
            
        except Exception as e:
            logger.error(f"Error refreshing feeds: {e}")
            error_html = f"""
            <div style="background: #fef2f2; padding: 25px; border-radius: 15px; border: 1px solid #fecaca;">
                <h3 style="color: #dc2626; margin: 0 0 15px 0;">❌ Feed Refresh Failed</h3>
                <p style="color: #7f1d1d; margin: 0;">Error: {str(e)}</p>
            </div>
            """
            error_progress = self._create_progress_html(0, 0, "Refresh Failed")
            return error_html, error_progress
    
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
    
    def _create_stats_html(self, stats: dict = None) -> str:
        """Create statistics HTML display with modern stat cards"""
        if stats is None:
            # Get stats automatically
            try:
                stats = self.aggregator.db.get_statistics()
            except Exception as e:
                stats = {
                    'total_threats': 0,
                    'sources_count': len(Config.THREAT_FEEDS),
                    'recent_threats': 0,
                    'high_severity': 0,
                    'medium_severity': 0,
                    'total_iocs': 0,
                    'ai_analyzed': 0,
                    'last_update': 'Never'
                }
        
        # Ensure all required keys exist
        default_stats = {
            'total_threats': 0,
            'sources_count': len(Config.THREAT_FEEDS),
            'recent_threats': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'total_iocs': 0,
            'ai_analyzed': 0,
            'last_update': 'Never'
        }
        
        # Merge with defaults
        for key, default_value in default_stats.items():
            if key not in stats:
                stats[key] = default_value
        
        return f"""
        <div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 18px; margin: 18px 0;'>
            <div class='stat-card'><span class='stat-icon'>🛡️</span>
                <div><div style='font-size: 15px; color: #a5b4fc;'>Total Threats</div>
                <div style='font-size: 2.1rem; font-weight: bold;'>{stats['total_threats']}</div></div>
            </div>
            <div class='stat-card'><span class='stat-icon'>🚨</span>
                <div><div style='font-size: 15px; color: #fca5a5;'>High Severity</div>
                <div style='font-size: 2.1rem; font-weight: bold;'>{stats['high_severity']}</div></div>
            </div>
            <div class='stat-card'><span class='stat-icon'>⚠️</span>
                <div><div style='font-size: 15px; color: #fdba74;'>Medium Severity</div>
                <div style='font-size: 2.1rem; font-weight: bold;'>{stats['medium_severity']}</div></div>
            </div>
            <div class='stat-card'><span class='stat-icon'>📊</span>
                <div><div style='font-size: 15px; color: #6ee7b7;'>Total IOCs</div>
                <div style='font-size: 2.1rem; font-weight: bold;'>{stats['total_iocs']}</div></div>
            </div>
        </div>
        <div style='background: linear-gradient(135deg, #374151 0%, #1f2937 100%); 
                    padding: 14px; border-radius: 10px; margin: 12px 0 18px 0;
                    box-shadow: 0 2px 8px rgba(55, 65, 81, 0.18); border: 1px solid rgba(75, 85, 99, 0.18);'>
            <span style='color: #fff; font-size: 15px; font-weight: 600; text-align: center; text-shadow: 1px 1px 2px rgba(0,0,0,0.2);'>
                🕒 Last Update: {stats['last_update']}
            </span>
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
    
    # New real-time methods for the revamped dashboard
    
    def _get_professional_css(self) -> str:
        """Professional cybersecurity CSS theme"""
        return """
        /* Professional Cybersecurity Theme */
        @import url('https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400;600;700&display=swap');
        
        .gradio-container {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%) !important;
            min-height: 100vh;
            font-family: 'Source Sans Pro', sans-serif !important;
        }
        
        .block {
            background: rgba(248, 250, 252, 0.98) !important;
            border-radius: 16px !important;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3) !important;
            border: 1px solid rgba(71, 85, 105, 0.3) !important;
            margin: 10px !important;
        }
        
        /* Professional Tab Styling */
        .tab-nav {
            background: linear-gradient(135deg, #1e40af, #1d4ed8) !important;
            border-radius: 12px !important;
            padding: 8px !important;
            box-shadow: 0 8px 16px rgba(30, 64, 175, 0.3) !important;
        }
        
        .tab-nav button {
            color: #e0e7ff !important;
            font-weight: 600 !important;
            border-radius: 10px !important;
            transition: all 0.3s ease !important;
            padding: 12px 20px !important;
        }
        
        .tab-nav button:hover {
            background: rgba(224, 231, 255, 0.15) !important;
            transform: translateY(-2px) !important;
        }
        
        .tab-nav button.selected {
            background: linear-gradient(135deg, #ffffff, #f1f5f9) !important;
            color: #1e40af !important;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2) !important;
        }
        
        /* Professional Button Styling */
        .btn-primary {
            background: linear-gradient(135deg, #2563eb, #1d4ed8) !important;
            border: none !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            border-radius: 10px !important;
            padding: 12px 24px !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 6px 16px rgba(37, 99, 235, 0.3) !important;
        }
        
        .btn-primary:hover {
            transform: translateY(-3px) !important;
            box-shadow: 0 10px 24px rgba(37, 99, 235, 0.4) !important;
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #64748b, #475569) !important;
            border: none !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            border-radius: 10px !important;
            padding: 12px 24px !important;
            transition: all 0.3s ease !important;
        }
        
        /* Form Styling */
        input, textarea, select {
            border: 2px solid #e2e8f0 !important;
            border-radius: 10px !important;
            padding: 12px 16px !important;
            font-size: 14px !important;
            transition: all 0.3s ease !important;
            background: #ffffff !important;
        }
        
        input:focus, textarea:focus, select:focus {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.1) !important;
        }
        
        /* Animation for pulse effect */
        @keyframes pulse {
            0%, 100% { opacity: 0.5; }
            50% { opacity: 1; }
        }
        
        /* Progress bar styling */
        .progress-container {
            background: #e5e7eb;
            border-radius: 10px;
            overflow: hidden;
            height: 8px;
            margin: 10px 0;
        }
        
        .progress-bar {
            background: linear-gradient(90deg, #22d3ee, #2563eb);
            height: 100%;
            transition: width 0.3s ease;
            border-radius: 10px;
        }
        
        /* Live indicator */
        @keyframes live-pulse {
            0% { background-color: #ef4444; }
            50% { background-color: #dc2626; }
            100% { background-color: #ef4444; }
        }
        
        .live-indicator {
            animation: live-pulse 2s infinite;
            border-radius: 50%;
            width: 12px;
            height: 12px;
            display: inline-block;
            margin-right: 8px;
        }
        """
    
    def _create_progress_html(self, current: int, total: int, status: str) -> str:
        """Create professional progress indicator"""
        if total == 0:
            progress_percent = 0
        else:
            progress_percent = (current / total) * 100
            
        status_color = "#22c55e" if status == "Complete" else "#3b82f6" if "Processing" in status else "#64748b"
        
        return f"""
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); 
                   padding: 20px; border-radius: 12px; border-left: 4px solid {status_color};">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <h4 style="margin: 0; color: #1e293b;">📊 Processing Status</h4>
                <span style="background: {status_color}; color: white; padding: 4px 12px; 
                           border-radius: 20px; font-size: 12px; font-weight: 600;">
                    {status}
                </span>
            </div>
            
            <div style="margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span style="color: #475569;">Progress: {current} / {total}</span>
                    <span style="color: #475569; font-weight: 600;">{progress_percent:.1f}%</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar" style="width: {progress_percent}%;"></div>
                </div>
            </div>
            
            {f'<div class="live-indicator"></div><span style="color: #059669; font-weight: 600;">Live Processing Active</span>' if "Processing" in status else ''}
        </div>
        """
    
    def _start_live_feed(self):
        """Start real-time threat feed processing with streaming updates"""
        try:
            # Immediate response showing processing started
            processing_html = """
            <div style="background: linear-gradient(135deg, #3b82f6, #1d4ed8); 
                       padding: 30px; border-radius: 12px; text-align: center; color: white;">
                <div style="font-size: 1.5em; margin-bottom: 15px;">⚡</div>
                <h3 style="margin-bottom: 15px;">Starting Real-time Feed Collection</h3>
                <p style="color: #cbd5e1; margin-bottom: 20px;">Initializing threat intelligence aggregation...</p>
                <div class="live-indicator"></div>
                <span style="font-weight: 600;">Live Feed Starting</span>
            </div>
            """
            
            progress_html = self._create_progress_html(0, len(Config.THREAT_FEEDS), "Starting")
            stats_html = self._create_stats_html()
            
            # Start background processing
            def background_processing():
                try:
                    # Actually process the feeds using the correct method
                    self.aggregator.refresh_feeds()
                except Exception as e:
                    logger.error(f"Error in background processing: {e}")
            
            # Start processing in background thread
            threading.Thread(target=background_processing, daemon=True).start()
            
            # Wait a moment then show results
            time.sleep(2)
            
            # Get and display results
            threats = self.aggregator.db.get_recent_threats(limit=20)
            
            return (
                self._create_threat_stream_html(threats),
                self._create_progress_html(len(Config.THREAT_FEEDS), len(Config.THREAT_FEEDS), "Complete"),
                self._create_stats_html()
            )
            
        except Exception as e:
            error_html = f"""
            <div style="background: #fef2f2; padding: 20px; border-radius: 10px; border-left: 4px solid #ef4444;">
                <h3 style="color: #dc2626; margin: 0;">❌ Processing Error</h3>
                <p style="color: #991b1b; margin: 10px 0 0 0;">Error: {str(e)}</p>
            </div>
            """
            return (
                error_html,
                self._create_progress_html(0, 0, "Error"),
                self._create_stats_html()
            )

    def _create_threat_stream_html(self, threats: List[Dict]) -> str:
        """Create real-time threat stream with professional styling"""
        if not threats:
            return """
            <div style="background: linear-gradient(135deg, #f1f5f9, #e2e8f0); 
                       padding: 40px; border-radius: 12px; text-align: center;">
                <div style="font-size: 3em; margin-bottom: 20px; color: #64748b;">🛡️</div>
                <h3 style="color: #475569; margin-bottom: 10px;">No Recent Threats</h3>
                <p style="color: #64748b;">Start the live feed to see real-time threat intelligence</p>
            </div>
            """
        
        html = f"""
        <div style="max-height: 700px; overflow-y: auto; padding: 10px;">
            <div style="background: linear-gradient(135deg, #1e40af, #1d4ed8); 
                       padding: 20px; border-radius: 12px; margin-bottom: 20px; color: white; text-align: center;">
                <h2 style="margin: 0; font-weight: 700;">🔴 Live Threat Intelligence Stream</h2>
                <p style="margin: 10px 0 0 0; color: #e0e7ff;">Showing {len(threats)} recent threats • Real-time updates</p>
            </div>
        """
        
        for i, threat in enumerate(threats):
            # Convert ThreatIntelItem to dict if needed
            if hasattr(threat, 'to_dict'):
                threat_dict = threat.to_dict()
            else:
                threat_dict = threat
            
            # Determine severity styling
            severity = threat_dict.get('severity', 'Unknown').lower()
            if severity == 'critical':
                border_color = "#dc2626"
                bg_color = "#fef2f2"
                icon = "🚨"
                severity_badge = "background: #dc2626; color: white;"
            elif severity == 'high':
                border_color = "#ea580c"
                bg_color = "#fff7ed"
                icon = "⚠️"
                severity_badge = "background: #ea580c; color: white;"
            elif severity == 'medium':
                border_color = "#d97706"
                bg_color = "#fffbeb"
                icon = "⚡"
                severity_badge = "background: #d97706; color: white;"
            else:
                border_color = "#059669"
                bg_color = "#f0fdf4"
                icon = "ℹ️"
                severity_badge = "background: #059669; color: white;"
            
            # Format IOCs
            iocs = threat_dict.get('iocs', {})
            # If iocs is a dict, convert to list of all IOCs
            if isinstance(iocs, dict):
                all_iocs = []
                for ioc_type, ioc_list in iocs.items():
                    if isinstance(ioc_list, list):
                        all_iocs.extend(ioc_list)
                iocs = all_iocs
            elif not isinstance(iocs, list):
                iocs = []
                
            ioc_html = ""
            if iocs:
                ioc_html = "<div style='margin-top: 15px;'><strong style='color: #1e293b;'>IOCs:</strong><br>"
                for ioc in iocs[:3]:  # Show first 3 IOCs
                    ioc_html += f"<span style='background: #f1f5f9; padding: 4px 8px; border-radius: 6px; margin: 2px; display: inline-block; font-family: monospace; font-size: 12px;'>{ioc}</span>"
                if len(iocs) > 3:
                    ioc_html += f"<span style='color: #64748b; font-size: 12px;'> +{len(iocs)-3} more</span>"
                ioc_html += "</div>"
            
            # AI Analysis summary
            ai_summary = threat_dict.get('ai_analysis', {}).get('summary', threat_dict.get('summary', 'No analysis available'))
            if len(ai_summary) > 200:
                ai_summary = ai_summary[:200] + "..."
            
            html += f"""
            <div style="background: {bg_color}; padding: 20px; border-radius: 12px; 
                       border-left: 4px solid {border_color}; margin-bottom: 15px; 
                       box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
                
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <div style="display: flex; align-items: center;">
                        <span style="font-size: 1.2em; margin-right: 10px;">{icon}</span>
                        <h4 style="margin: 0; color: #1e293b; font-weight: 600;">
                            {threat_dict.get('title', 'Unknown Threat')[:80]}
                        </h4>
                    </div>
                    <span style="{severity_badge} padding: 4px 12px; border-radius: 20px; 
                                font-size: 12px; font-weight: 600; text-transform: uppercase;">
                        {severity}
                    </span>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <strong style="color: #374151;">Source:</strong> 
                    <span style="color: #6b7280;">{threat_dict.get('source', 'Unknown')}</span>
                    <span style="margin-left: 20px; color: #6b7280; font-size: 14px;">
                        🕒 {threat_dict.get('published', 'Unknown time')}
                    </span>
                </div>
                
                <div style="color: #4b5563; line-height: 1.5; margin-bottom: 15px;">
                    {threat_dict.get('description', 'No description available')[:300]}
                    {'...' if len(threat_dict.get('description', '')) > 300 else ''}
                </div>
                
                {ioc_html}
                
                <div style="background: rgba(59, 130, 246, 0.1); padding: 15px; border-radius: 8px; margin-top: 15px;">
                    <strong style="color: #1e40af;">🤖 AI Analysis:</strong><br>
                    <span style="color: #374151; font-style: italic;">{ai_summary}</span>
                </div>
                
                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e5e7eb; 
                           font-size: 12px; color: #6b7280;">
                    ID: {threat_dict.get('id', 'N/A')} • 
                    Processed: {threat_dict.get('processed_at', threat_dict.get('published', 'Unknown'))}
                </div>
            </div>
            """
        
        html += "</div>"
        return html

    # Advanced feature methods
    def _run_threat_hunt(self):
        """Run quick threat hunting on current data"""
        if not ADVANCED_FEATURES_AVAILABLE:
            return (
                "<div style='text-align: center; padding: 40px; color: #dc2626;'>Advanced features not available</div>",
                self._create_progress_html(0, 0, "Feature Not Available")
            )
        
        try:
            # Run basic threat hunting
            hunt_results = asyncio.run(self.threat_hunter.run_automated_hunt())
            
            # Create summary display
            hunt_html = f"""
            <div style="background: linear-gradient(135deg, #1e40af, #1d4ed8); 
                       padding: 20px; border-radius: 12px; color: white; margin-bottom: 20px;">
                <h3 style="margin: 0;">🎯 Threat Hunting Results</h3>
                <p style="margin: 10px 0 0 0;">Analyzed {hunt_results.get('total_threats_analyzed', 0)} threats</p>
            </div>
            """
            
            risk_score = hunt_results.get('risk_score', 0)
            hunt_html += f"""
            <div style="background: #f8fafc; padding: 20px; border-radius: 12px; margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h4 style="margin: 0; color: #1e293b;">Overall Risk Score</h4>
                    <span style="font-size: 2em; font-weight: bold; color: {'#dc2626' if risk_score > 70 else '#ea580c' if risk_score > 40 else '#059669'};">
                        {risk_score}/100
                    </span>
                </div>
            </div>
            """
            
            return (hunt_html, self._create_progress_html(100, 100, "Hunt Complete"))
            
        except Exception as e:
            logger.error(f"Error in threat hunting: {e}")
            return (
                f"<div style='color: #dc2626;'>Error running threat hunt: {str(e)}</div>",
                self._create_progress_html(0, 0, "Hunt Failed")
            )
    
    def _generate_threat_map(self):
        """Generate comprehensive threat analytics and visualization"""
        try:
            # Get comprehensive threat data
            threats = self.aggregator.db.get_recent_threats(limit=100)
            ioc_stats = self.aggregator.db.get_ioc_statistics()
            
            if not threats:
                return self._create_no_analytics_data()
            
            # Analyze threats for comprehensive dashboard
            analytics_data = self._analyze_threats_for_dashboard(threats, ioc_stats)
            
            return self._create_comprehensive_analytics_display(analytics_data)
            
        except Exception as e:
            logger.error(f"Error generating threat analytics: {e}")
            return f"<div style='color: #dc2626; padding: 20px;'>Error generating analytics: {str(e)}</div>"
    
    def _create_no_analytics_data(self):
        """Create display when no analytics data is available"""
        return """
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); padding: 40px; border-radius: 20px; text-align: center;">
            <div style="background: linear-gradient(135deg, #6366f1, #4f46e5); color: white; padding: 30px; border-radius: 15px; margin-bottom: 30px;">
                <h2 style="margin: 0 0 15px 0; font-size: 2.2em;">📊 Advanced Threat Analytics</h2>
                <p style="margin: 0; font-size: 1.1em; opacity: 0.9;">Comprehensive Intelligence Dashboard</p>
            </div>
            
            <div style="background: #fef3c7; padding: 25px; border-radius: 15px; border-left: 4px solid #f59e0b; margin-bottom: 25px;">
                <h3 style="margin: 0 0 10px 0; color: #92400e;">📈 No Analytics Data Available</h3>
                <p style="margin: 0; color: #92400e;">Start collecting threat intelligence to generate advanced analytics and visualizations.</p>
            </div>
            
            <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h4 style="margin: 0 0 20px 0; color: #1e293b;">🚀 Available Analytics Features</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px;">
                    <div style="padding: 20px; background: #f8fafc; border-radius: 10px; border-left: 4px solid #3b82f6;">
                        <h5 style="margin: 0 0 10px 0; color: #1e293b;">🌍 Threat Geography</h5>
                        <p style="margin: 0; color: #64748b; font-size: 0.9em;">Global threat distribution and attack sources mapping</p>
                    </div>
                    <div style="padding: 20px; background: #f8fafc; border-radius: 10px; border-left: 4px solid #10b981;">
                        <h5 style="margin: 0 0 10px 0; color: #1e293b;">📈 Threat Trends</h5>
                        <p style="margin: 0; color: #64748b; font-size: 0.9em;">Timeline analysis and emerging threat patterns</p>
                    </div>
                    <div style="padding: 20px; background: #f8fafc; border-radius: 10px; border-left: 4px solid #f59e0b;">
                        <h5 style="margin: 0 0 10px 0; color: #1e293b;">🎯 IOC Analysis</h5>
                        <p style="margin: 0; color: #64748b; font-size: 0.9em;">Indicator frequency and threat actor correlation</p>
                    </div>
                    <div style="padding: 20px; background: #f8fafc; border-radius: 10px; border-left: 4px solid #ef4444;">
                        <h5 style="margin: 0 0 10px 0; color: #1e293b;">⚠️ Risk Assessment</h5>
                        <p style="margin: 0; color: #64748b; font-size: 0.9em;">Severity distribution and risk scoring</p>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _analyze_threats_for_dashboard(self, threats: list, ioc_stats: dict) -> dict:
        """Analyze threats for comprehensive dashboard"""
        analytics = {
            'total_threats': len(threats),
            'severity_distribution': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'source_distribution': {},
            'recent_activity': [],
            'top_threat_types': {},
            'ioc_statistics': ioc_stats,
            'timeline_data': [],
            'threat_actors': {},
            'attack_vectors': {}
        }
        
        # Analyze each threat
        for threat in threats:
            # Severity distribution
            analytics['severity_distribution'][threat.severity] = analytics['severity_distribution'].get(threat.severity, 0) + 1
            
            # Source distribution
            analytics['source_distribution'][threat.source] = analytics['source_distribution'].get(threat.source, 0) + 1
            
            # Timeline data
            analytics['timeline_data'].append({
                'date': threat.published_date,
                'severity': threat.severity,
                'title': threat.title
            })
            
            # Extract threat types from title/summary
            threat_text = f"{threat.title} {threat.summary}".lower()
            for threat_type in ['ransomware', 'apt', 'malware', 'phishing', 'ddos', 'vulnerability', 'exploit']:
                if threat_type in threat_text:
                    analytics['top_threat_types'][threat_type] = analytics['top_threat_types'].get(threat_type, 0) + 1
        
        # Sort distributions
        analytics['source_distribution'] = dict(sorted(analytics['source_distribution'].items(), key=lambda x: x[1], reverse=True)[:10])
        analytics['top_threat_types'] = dict(sorted(analytics['top_threat_types'].items(), key=lambda x: x[1], reverse=True)[:8])
        
        return analytics
    
    def _create_comprehensive_analytics_display(self, analytics: dict) -> str:
        """Create comprehensive analytics display"""
        html = f"""
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); padding: 30px; border-radius: 20px;">
            <div style="background: linear-gradient(135deg, #6366f1, #4f46e5); color: white; padding: 25px; border-radius: 15px; margin-bottom: 30px;">
                <h2 style="margin: 0 0 15px 0; font-size: 2em;">📊 Advanced Threat Intelligence Analytics</h2>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 20px;">
                    <div style="text-align: center;">
                        <div style="font-size: 2.2em; font-weight: bold;">{analytics['total_threats']}</div>
                        <div style="opacity: 0.9;">Total Threats</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2.2em; font-weight: bold;">{analytics['ioc_statistics']['unique_ips']}</div>
                        <div style="opacity: 0.9;">Unique IPs</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2.2em; font-weight: bold;">{analytics['ioc_statistics']['unique_domains']}</div>
                        <div style="opacity: 0.9;">Domains</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2.2em; font-weight: bold;">{len(analytics['source_distribution'])}</div>
                        <div style="opacity: 0.9;">Sources</div>
                    </div>
                </div>
            </div>
            
            <!-- Threat Severity Analysis -->
            <div style="background: white; padding: 25px; border-radius: 15px; margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 20px 0; color: #1e293b;">⚠️ Threat Severity Distribution</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px;">
        """
        
        severity_colors = {
            'Critical': '#dc2626',
            'High': '#ea580c', 
            'Medium': '#d97706',
            'Low': '#059669'
        }
        
        total_threats = sum(analytics['severity_distribution'].values())
        for severity, count in analytics['severity_distribution'].items():
            if count > 0:
                percentage = round((count / total_threats) * 100, 1) if total_threats > 0 else 0
                html += f"""
                <div style="background: {severity_colors[severity]}; color: white; padding: 20px; border-radius: 12px; text-align: center;">
                    <div style="font-size: 2em; font-weight: bold; margin-bottom: 5px;">{count}</div>
                    <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">{severity}</div>
                    <div style="font-size: 0.8em; opacity: 0.8;">({percentage}%)</div>
                </div>
                """
        
        html += """
                </div>
            </div>
            
            <!-- IOC Intelligence Overview -->
            <div style="background: white; padding: 25px; border-radius: 15px; margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 20px 0; color: #1e293b;">🔍 IOC Intelligence Overview</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
        """
        
        ioc_data = [
            ('🌐 IP Addresses', analytics['ioc_statistics']['unique_ips'], '#3b82f6'),
            ('🌍 Domains', analytics['ioc_statistics']['unique_domains'], '#10b981'),
            ('🔒 File Hashes', analytics['ioc_statistics']['unique_hashes'], '#f59e0b'),
            ('🔗 URLs', analytics['ioc_statistics']['unique_urls'], '#ef4444')
        ]
        
        for label, count, color in ioc_data:
            html += f"""
            <div style="background: {color}; color: white; padding: 20px; border-radius: 12px; text-align: center;">
                <div style="font-size: 1.8em; font-weight: bold; margin-bottom: 8px;">{count}</div>
                <div style="font-size: 0.9em; opacity: 0.9;">{label}</div>
            </div>
            """
        
        html += """
                </div>
            </div>
            
            <!-- Top Threat Sources -->
            <div style="background: white; padding: 25px; border-radius: 15px; margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 20px 0; color: #1e293b;">📰 Top Threat Intelligence Sources</h3>
                <div style="display: grid; gap: 10px;">
        """
        
        for idx, (source, count) in enumerate(list(analytics['source_distribution'].items())[:5], 1):
            percentage = round((count / analytics['total_threats']) * 100, 1) if analytics['total_threats'] > 0 else 0
            html += f"""
            <div style="background: #f8fafc; padding: 15px; border-radius: 10px; border-left: 4px solid #3b82f6;">
                <div style="display: flex; justify-content: between; align-items: center;">
                    <div>
                        <span style="font-weight: bold; color: #1e293b;">#{idx}. {source}</span>
                    </div>
                    <div>
                        <span style="background: #3b82f6; color: white; padding: 6px 12px; border-radius: 15px; font-size: 0.9em; font-weight: bold;">
                            {count} threats ({percentage}%)
                        </span>
                    </div>
                </div>
            </div>
            """
        
        html += """
                </div>
            </div>
            
            <!-- Threat Types Analysis -->
        """
        
        if analytics['top_threat_types']:
            html += """
            <div style="background: white; padding: 25px; border-radius: 15px; margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 20px 0; color: #1e293b;">🎯 Top Threat Types Detected</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
            """
            
            threat_type_colors = ['#dc2626', '#ea580c', '#d97706', '#059669', '#0891b2', '#7c3aed', '#c2410c', '#be123c']
            for idx, (threat_type, count) in enumerate(analytics['top_threat_types'].items()):
                color = threat_type_colors[idx % len(threat_type_colors)]
                html += f"""
                <div style="background: {color}; color: white; padding: 20px; border-radius: 12px; text-align: center;">
                    <div style="font-size: 1.6em; font-weight: bold; margin-bottom: 8px;">{count}</div>
                    <div style="font-size: 0.9em; opacity: 0.9; text-transform: capitalize;">{threat_type}</div>
                </div>
                """
            
            html += "</div></div>"
        
        # Add top domains if available
        if analytics['ioc_statistics']['top_domains']:
            html += """
            <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h3 style="margin: 0 0 20px 0; color: #1e293b;">🌍 Most Frequently Seen Malicious Domains</h3>
                <div style="display: grid; gap: 10px;">
            """
            
            for idx, (domain, count) in enumerate(list(analytics['ioc_statistics']['top_domains'].items())[:5], 1):
                html += f"""
                <div style="background: #fef2f2; padding: 15px; border-radius: 10px; border-left: 4px solid #ef4444;">
                    <div style="display: flex; justify-content: between; align-items: center;">
                        <div>
                            <span style="font-weight: bold; color: #dc2626; font-family: monospace;">#{idx}. {domain}</span>
                        </div>
                        <div>
                            <span style="background: #ef4444; color: white; padding: 6px 12px; border-radius: 15px; font-size: 0.9em; font-weight: bold;">
                                {count} occurrences
                            </span>
                        </div>
                    </div>
                </div>
                """
            
            html += "</div></div>"
        
        html += "</div>"
        return html
    
    def _generate_timeline(self):
        """Generate comprehensive threat timeline analysis"""
        try:
            threats = self.aggregator.db.get_recent_threats(limit=50)
            
            if not threats:
                return self._create_no_timeline_data()
            
            return self._create_comprehensive_timeline_display(threats)
            
        except Exception as e:
            logger.error(f"Error generating timeline: {e}")
            return f"<div style='color: #dc2626; padding: 20px;'>Error generating timeline: {str(e)}</div>"
    
    def _create_no_timeline_data(self):
        """Create display when no timeline data is available"""
        return """
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); padding: 40px; border-radius: 20px; text-align: center;">
            <div style="background: linear-gradient(135deg, #059669, #047857); color: white; padding: 30px; border-radius: 15px; margin-bottom: 30px;">
                <h2 style="margin: 0 0 15px 0; font-size: 2.2em;">📈 Threat Intelligence Timeline</h2>
                <p style="margin: 0; font-size: 1.1em; opacity: 0.9;">Temporal Analysis & Trends</p>
            </div>
            
            <div style="background: #fef3c7; padding: 25px; border-radius: 15px; border-left: 4px solid #f59e0b;">
                <h3 style="margin: 0 0 10px 0; color: #92400e;">📊 No Timeline Data Available</h3>
                <p style="margin: 0; color: #92400e;">Start collecting threat intelligence to generate timeline analysis and trend visualization.</p>
            </div>
        </div>
        """
    
    def _create_comprehensive_timeline_display(self, threats: list) -> str:
        """Create comprehensive timeline display"""
        from datetime import datetime, timedelta
        from collections import defaultdict
        
        # Group threats by date
        timeline_data = defaultdict(list)
        severity_by_date = defaultdict(lambda: {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0})
        
        for threat in threats:
            try:
                # Parse date (handle different formats)
                date_str = threat.published_date
                if isinstance(date_str, str):
                    # Try different date formats
                    for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%m/%d/%Y', '%d/%m/%Y']:
                        try:
                            date_obj = datetime.strptime(date_str.split(' ')[0], fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        date_obj = datetime.now()  # fallback
                else:
                    date_obj = datetime.now()
                
                date_key = date_obj.strftime('%Y-%m-%d')
                timeline_data[date_key].append(threat)
                severity_by_date[date_key][threat.severity] += 1
                
            except Exception:
                # Handle parsing errors
                date_key = datetime.now().strftime('%Y-%m-%d')
                timeline_data[date_key].append(threat)
                severity_by_date[date_key][threat.severity] += 1
        
        # Sort dates
        sorted_dates = sorted(timeline_data.keys(), reverse=True)
        
        html = f"""
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); padding: 30px; border-radius: 20px;">
            <div style="background: linear-gradient(135deg, #059669, #047857); color: white; padding: 25px; border-radius: 15px; margin-bottom: 30px;">
                <h2 style="margin: 0 0 15px 0; font-size: 2em;">📈 Threat Intelligence Timeline</h2>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 20px;">
                    <div style="text-align: center;">
                        <div style="font-size: 2.2em; font-weight: bold;">{len(threats)}</div>
                        <div style="opacity: 0.9;">Total Threats</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2.2em; font-weight: bold;">{len(sorted_dates)}</div>
                        <div style="opacity: 0.9;">Active Days</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2.2em; font-weight: bold;">{round(len(threats)/max(len(sorted_dates), 1), 1)}</div>
                        <div style="opacity: 0.9;">Avg/Day</div>
                    </div>
                </div>
            </div>
        """
        
        # Create timeline entries
        for idx, date in enumerate(sorted_dates[:10]):  # Show last 10 days
            threats_for_date = timeline_data[date]
            severity_counts = severity_by_date[date]
            
            # Calculate relative date
            try:
                date_obj = datetime.strptime(date, '%Y-%m-%d')
                days_ago = (datetime.now() - date_obj).days
                if days_ago == 0:
                    relative_date = "Today"
                elif days_ago == 1:
                    relative_date = "Yesterday"
                else:
                    relative_date = f"{days_ago} days ago"
            except:
                relative_date = "Unknown"
            
            # Determine dominant severity
            max_severity = max(severity_counts.items(), key=lambda x: x[1])
            severity_colors = {
                'Critical': '#dc2626',
                'High': '#ea580c', 
                'Medium': '#d97706',
                'Low': '#059669'
            }
            dominant_color = severity_colors.get(max_severity[0], '#6b7280')
            
            html += f"""
            <div style="background: white; padding: 25px; border-radius: 15px; margin-bottom: 20px; 
                       box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-left: 5px solid {dominant_color};">
                
                <div style="display: flex; justify-content: between; align-items: center; margin-bottom: 20px;">
                    <div>
                        <h3 style="margin: 0; color: #1e293b; font-size: 1.4em;">{date}</h3>
                        <p style="margin: 5px 0 0 0; color: #64748b; font-size: 0.9em;">{relative_date} • {len(threats_for_date)} threats detected</p>
                    </div>
                    <div style="text-align: right;">
                        <div style="background: {dominant_color}; color: white; padding: 8px 16px; border-radius: 20px; font-size: 0.9em; font-weight: bold;">
                            Peak: {max_severity[0]}
                        </div>
                    </div>
                </div>
                
                <!-- Severity breakdown for the day -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 10px; margin-bottom: 20px;">
            """
            
            for severity, count in severity_counts.items():
                if count > 0:
                    color = severity_colors[severity]
                    html += f"""
                    <div style="background: {color}; color: white; padding: 12px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 1.3em; font-weight: bold;">{count}</div>
                        <div style="font-size: 0.8em; opacity: 0.9;">{severity}</div>
                    </div>
                    """
            
            html += """
                </div>
                
                <!-- Top threats for the day -->
                <div style="background: #f8fafc; padding: 15px; border-radius: 10px;">
                    <h4 style="margin: 0 0 15px 0; color: #1e293b; font-size: 1.1em;">🎯 Notable Threats</h4>
            """
            
            # Show top 3 threats for the day
            for threat_idx, threat in enumerate(threats_for_date[:3], 1):
                threat_color = severity_colors.get(threat.severity, '#6b7280')
                html += f"""
                <div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 8px; 
                           border-left: 3px solid {threat_color};">
                    <div style="display: flex; justify-content: between; align-items: start;">
                        <div style="flex: 1;">
                            <span style="font-weight: bold; color: #1e293b; font-size: 0.95em;">
                                #{threat_idx}. {threat.title[:60]}{'...' if len(threat.title) > 60 else ''}
                            </span>
                            <div style="margin-top: 5px; color: #64748b; font-size: 0.85em;">
                                Source: {threat.source}
                            </div>
                        </div>
                        <div style="background: {threat_color}; color: white; padding: 4px 8px; 
                                   border-radius: 10px; font-size: 0.75em; font-weight: bold; margin-left: 10px;">
                            {threat.severity}
                        </div>
                    </div>
                </div>
                """
            
            if len(threats_for_date) > 3:
                html += f"""
                <div style="text-align: center; padding: 8px; color: #64748b; font-size: 0.9em; font-style: italic;">
                    ... and {len(threats_for_date) - 3} more threats
                </div>
                """
            
            html += "</div></div>"
        
        if len(sorted_dates) > 10:
            html += f"""
            <div style="background: #f1f5f9; padding: 20px; border-radius: 15px; text-align: center; border: 2px dashed #cbd5e1;">
                <span style="color: #475569; font-weight: 600;">
                    📊 Timeline shows last 10 days • {len(sorted_dates) - 10} more days available in database
                </span>
            </div>
            """
        
        html += "</div>"
        return html
    
    def _handle_chat_query(self, query: str):
        """Handle AI chat queries"""
        if not ADVANCED_FEATURES_AVAILABLE:
            return "<div style='text-align: center; padding: 40px; color: #dc2626;'>AI chat assistant not available</div>"
        
        if not query.strip():
            return "<div style='text-align: center; padding: 20px; color: #64748b;'>Please enter a question</div>"
        
        try:
            # Get context for the AI
            context = {
                'recent_threats': self.aggregator.db.get_recent_threats(limit=10)
            }
            
            response = asyncio.run(self.chat_assistant.process_chat_message(query, context))
            return response
            
        except Exception as e:
            logger.error(f"Error in chat query: {e}")
            return f"<div style='color: #dc2626;'>Error processing query: {str(e)}</div>"
    
    def _run_automated_hunt(self):
        """Run comprehensive automated threat hunting"""
        if not ADVANCED_FEATURES_AVAILABLE:
            return (
                "<div style='text-align: center; padding: 40px; color: #dc2626;'>Advanced hunting features not available</div>",
                "<div style='color: #dc2626;'>Feature not available</div>"
            )
        
        try:
            # Run comprehensive hunt
            hunt_results = asyncio.run(self.threat_hunter.run_automated_hunt())
            
            # Create comprehensive results display
            results_html = f"""
            <div style="background: linear-gradient(135deg, #1e40af, #1d4ed8); 
                       padding: 25px; border-radius: 15px; color: white; margin-bottom: 25px;">
                <h3 style="margin: 0 0 15px 0; font-size: 1.5em;">🎯 Automated Threat Hunting Report</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold;">{hunt_results.get('total_threats_analyzed', 0)}</div>
                        <div>Threats Analyzed</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #fbbf24;">{hunt_results.get('risk_score', 0)}</div>
                        <div>Risk Score</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #f87171;">{len(hunt_results.get('hunting_results', {}))}</div>
                        <div>Rules Triggered</div>
                    </div>
                </div>
            </div>
            """
            
            # Add hunting rule results
            hunting_results = hunt_results.get('hunting_results', {})
            if hunting_results:
                results_html += "<h4 style='color: #1e293b; margin: 20px 0 15px 0;'>🔍 Hunting Rule Results</h4>"
                
                for rule_id, result in hunting_results.items():
                    if isinstance(result, dict) and result.get('match_count', 0) > 0:
                        severity = result.get('severity', 'unknown')
                        severity_colors = {
                            'critical': '#dc2626',
                            'high': '#ea580c',
                            'medium': '#d97706',
                            'low': '#059669'
                        }
                        color = severity_colors.get(severity, '#6b7280')
                        
                        results_html += f"""
                        <div style="background: #f8fafc; border-left: 4px solid {color}; 
                                   padding: 15px; margin-bottom: 10px; border-radius: 8px;">
                            <div style="display: flex; justify-content: between; align-items: center;">
                                <strong style="color: #1e293b;">{result.get('rule_name', rule_id)}</strong>
                                <span style="background: {color}; color: white; padding: 4px 8px; 
                                           border-radius: 12px; font-size: 0.8em; margin-left: 10px;">
                                    {result.get('match_count', 0)} matches
                                </span>
                            </div>
                            <p style="color: #64748b; margin: 5px 0 0 0; font-size: 0.9em;">
                                {result.get('description', 'No description available')}
                            </p>
                        </div>
                        """
            
            # Add recommendations
            recommendations = hunt_results.get('recommendations', [])
            if recommendations:
                results_html += "<h4 style='color: #1e293b; margin: 20px 0 15px 0;'>💡 Recommendations</h4>"
                for rec in recommendations[:5]:  # Top 5 recommendations
                    results_html += f"""
                    <div style="background: #ecfdf5; border-left: 4px solid #10b981; 
                               padding: 12px; margin-bottom: 8px; border-radius: 6px;">
                        <span style="color: #065f46;">{rec}</span>
                    </div>
                    """
            
            status_html = f"""
            <div style="background: #10b981; color: white; padding: 15px; border-radius: 10px; text-align: center;">
                <strong>✅ Hunt Completed Successfully</strong><br>
                <small>Timestamp: {hunt_results.get('timestamp', 'Unknown')}</small>
            </div>
            """
            
            return (results_html, status_html)
            
        except Exception as e:
            logger.error(f"Error in automated hunting: {e}")
            return (
                f"<div style='color: #dc2626;'>Error running automated hunt: {str(e)}</div>",
                "<div style='background: #dc2626; color: white; padding: 15px; border-radius: 10px; text-align: center;'>❌ Hunt Failed</div>"
            )
    
    def _analyze_ioc(self, ioc: str):
        """Comprehensive IOC analysis with detailed intelligence"""
        if not ioc.strip():
            return self._create_ioc_welcome_message()
        
        try:
            ioc = ioc.strip()
            
            # Search in database
            results = self.aggregator.db.search_ioc(ioc)
            
            # Get IOC statistics
            ioc_stats = self.aggregator.db.get_ioc_statistics()
            
            # Determine IOC type
            ioc_type = self._determine_ioc_type(ioc)
            
            if not results:
                return self._create_no_results_display(ioc, ioc_type, ioc_stats)
            
            # Create comprehensive results display
            return self._create_comprehensive_ioc_results(ioc, ioc_type, results, ioc_stats)
            
        except Exception as e:
            logger.error(f"Error analyzing IOC: {e}")
            return self._create_error_display(ioc, str(e))
    
    def _create_ioc_welcome_message(self):
        """Create welcome message for IOC analysis"""
        return """
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); padding: 40px; border-radius: 20px; text-align: center;">
            <div style="background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; padding: 30px; border-radius: 15px; margin-bottom: 30px;">
                <h2 style="margin: 0 0 15px 0; font-size: 2.2em;">🔍 IOC Intelligence Center</h2>
                <p style="margin: 0; font-size: 1.1em; opacity: 0.9;">Advanced Indicator of Compromise Analysis</p>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px;">
                <div style="background: white; padding: 25px; border-radius: 12px; border-left: 4px solid #3b82f6; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                    <h4 style="margin: 0 0 10px 0; color: #1e293b;">🌐 IP Addresses</h4>
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">Analyze malicious IPs, C2 servers, and attack sources</p>
                </div>
                <div style="background: white; padding: 25px; border-radius: 12px; border-left: 4px solid #10b981; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                    <h4 style="margin: 0 0 10px 0; color: #1e293b;">🌍 Domains</h4>
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">Track malicious domains, phishing sites, and C2 infrastructure</p>
                </div>
                <div style="background: white; padding: 25px; border-radius: 12px; border-left: 4px solid #f59e0b; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                    <h4 style="margin: 0 0 10px 0; color: #1e293b;">🔒 File Hashes</h4>
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">Identify malware samples, trojans, and malicious files</p>
                </div>
                <div style="background: white; padding: 25px; border-radius: 12px; border-left: 4px solid #ef4444; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                    <h4 style="margin: 0 0 10px 0; color: #1e293b;">🔗 URLs</h4>
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">Detect malicious URLs, exploit kits, and attack vectors</p>
                </div>
            </div>
            
            <div style="background: #f1f5f9; padding: 20px; border-radius: 12px; border: 2px dashed #cbd5e1;">
                <p style="margin: 0; color: #475569; font-size: 1.1em;">
                    💡 <strong>Enter any IOC above to begin analysis:</strong><br>
                    Examples: 192.168.1.1, malicious.com, a1b2c3d4e5f6..., http://bad-site.com
                </p>
            </div>
        </div>
        """
    
    def _determine_ioc_type(self, ioc: str) -> str:
        """Determine the type of IOC"""
        import re
        
        # IP address pattern
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        # Hash patterns
        md5_pattern = r'^[a-fA-F0-9]{32}$'
        sha1_pattern = r'^[a-fA-F0-9]{40}$'
        sha256_pattern = r'^[a-fA-F0-9]{64}$'
        # URL pattern
        url_pattern = r'^https?://.+'
        
        if re.match(ip_pattern, ioc):
            return 'IP Address'
        elif re.match(url_pattern, ioc):
            return 'URL'
        elif re.match(sha256_pattern, ioc):
            return 'SHA256 Hash'
        elif re.match(sha1_pattern, ioc):
            return 'SHA1 Hash'
        elif re.match(md5_pattern, ioc):
            return 'MD5 Hash'
        elif re.match(domain_pattern, ioc):
            return 'Domain'
        else:
            return 'Unknown'
    
    def _create_no_results_display(self, ioc: str, ioc_type: str, ioc_stats: dict):
        """Create display for when no results are found"""
        return f"""
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); padding: 30px; border-radius: 20px;">
            <div style="background: #fef3c7; padding: 25px; border-radius: 15px; border-left: 4px solid #f59e0b; margin-bottom: 25px;">
                <h3 style="margin: 0 0 15px 0; color: #92400e;">🔍 IOC Analysis: {ioc}</h3>
                <div style="display: grid; grid-template-columns: auto 1fr; gap: 15px; align-items: center;">
                    <div style="background: #fbbf24; color: white; padding: 8px 16px; border-radius: 20px; font-size: 0.9em; font-weight: bold;">
                        {ioc_type}
                    </div>
                    <div style="color: #92400e; font-weight: 600;">
                        No matches found in current threat intelligence database
                    </div>
                </div>
            </div>
            
            <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h4 style="margin: 0 0 20px 0; color: #1e293b;">📊 Current IOC Database Statistics</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
                    <div style="text-align: center; padding: 15px; background: #f8fafc; border-radius: 10px;">
                        <div style="font-size: 1.8em; font-weight: bold; color: #3b82f6;">{ioc_stats['unique_ips']}</div>
                        <div style="color: #64748b; font-size: 0.9em;">Unique IPs</div>
                    </div>
                    <div style="text-align: center; padding: 15px; background: #f8fafc; border-radius: 10px;">
                        <div style="font-size: 1.8em; font-weight: bold; color: #10b981;">{ioc_stats['unique_domains']}</div>
                        <div style="color: #64748b; font-size: 0.9em;">Unique Domains</div>
                    </div>
                    <div style="text-align: center; padding: 15px; background: #f8fafc; border-radius: 10px;">
                        <div style="font-size: 1.8em; font-weight: bold; color: #f59e0b;">{ioc_stats['unique_hashes']}</div>
                        <div style="color: #64748b; font-size: 0.9em;">File Hashes</div>
                    </div>
                    <div style="text-align: center; padding: 15px; background: #f8fafc; border-radius: 10px;">
                        <div style="font-size: 1.8em; font-weight: bold; color: #ef4444;">{ioc_stats['unique_urls']}</div>
                        <div style="color: #64748b; font-size: 0.9em;">URLs</div>
                    </div>
                </div>
            </div>
            
            <div style="background: #eff6ff; padding: 20px; border-radius: 12px; border: 1px solid #bfdbfe; margin-top: 20px;">
                <p style="margin: 0; color: #1e40af;">
                    💡 <strong>Recommendation:</strong> This IOC is not currently in our threat intelligence database. 
                    Consider checking external threat intelligence sources or adding it to your watchlist for future monitoring.
                </p>
            </div>
        </div>
        """
    
    def _create_comprehensive_ioc_results(self, ioc: str, ioc_type: str, results: list, ioc_stats: dict):
        """Create comprehensive IOC results display"""
        results_html = f"""
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); padding: 30px; border-radius: 20px;">
            <div style="background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; padding: 25px; border-radius: 15px; margin-bottom: 25px;">
                <h3 style="margin: 0 0 15px 0; font-size: 1.8em;">🚨 IOC Intelligence Report: {ioc}</h3>
                <div style="display: grid; grid-template-columns: auto auto 1fr; gap: 20px; align-items: center;">
                    <div style="background: rgba(255,255,255,0.2); padding: 10px 20px; border-radius: 20px; font-weight: bold;">
                        {ioc_type}
                    </div>
                    <div style="background: rgba(255,255,255,0.2); padding: 10px 20px; border-radius: 20px; font-weight: bold;">
                        {len(results)} Threat(s) Found
                    </div>
                    <div style="text-align: right; font-size: 0.9em; opacity: 0.9;">
                        ⚠️ ACTIVE THREAT INDICATOR
                    </div>
                </div>
            </div>
        """
        
        # Add threat severity summary
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for threat in results:
            severity_counts[threat.severity] = severity_counts.get(threat.severity, 0) + 1
        
        results_html += f"""
        <div style="background: white; padding: 25px; border-radius: 15px; margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
            <h4 style="margin: 0 0 20px 0; color: #1e293b;">📊 Threat Severity Distribution</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px;">
        """
        
        severity_colors = {
            'Critical': '#dc2626',
            'High': '#ea580c', 
            'Medium': '#d97706',
            'Low': '#059669'
        }
        
        for severity, count in severity_counts.items():
            if count > 0:
                results_html += f"""
                <div style="text-align: center; padding: 15px; background: {severity_colors[severity]}; color: white; border-radius: 10px;">
                    <div style="font-size: 1.6em; font-weight: bold;">{count}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">{severity}</div>
                </div>
                """
        
        results_html += "</div></div>"
        
        # Add detailed threat information
        results_html += f"""
        <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
            <h4 style="margin: 0 0 20px 0; color: #1e293b;">🔍 Detailed Threat Analysis</h4>
        """
        
        for idx, threat in enumerate(results[:5], 1):  # Show top 5 matches
            color = severity_colors.get(threat.severity, '#6b7280')
            
            results_html += f"""
            <div style="background: #f8fafc; padding: 20px; border-radius: 12px; margin-bottom: 15px; 
                       border-left: 5px solid {color}; position: relative;">
                <div style="position: absolute; top: 15px; right: 15px; background: {color}; color: white; 
                           padding: 6px 12px; border-radius: 15px; font-size: 0.8em; font-weight: bold;">
                    #{idx} • {threat.severity}
                </div>
                
                <h5 style="margin: 0 0 15px 0; color: #1e293b; padding-right: 100px;">{threat.title}</h5>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 15px 0;">
                    <div style="background: white; padding: 12px; border-radius: 8px; border: 1px solid #e2e8f0;">
                        <strong style="color: #1e40af;">📰 Source:</strong> 
                        <span style="color: #334155;">{threat.source}</span>
                    </div>
                    <div style="background: white; padding: 12px; border-radius: 8px; border: 1px solid #e2e8f0;">
                        <strong style="color: #1e40af;">📅 Date:</strong> 
                        <span style="color: #334155;">{threat.published_date}</span>
                    </div>
                </div>
                
                <div style="background: white; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0; margin: 15px 0;">
                    <strong style="color: #1e40af;">📝 Summary:</strong>
                    <p style="margin: 8px 0 0 0; color: #374151; line-height: 1.6;">
                        {threat.summary[:300]}{'...' if len(threat.summary) > 300 else ''}
                    </p>
                </div>
                
                <div style="background: #fef3c7; padding: 12px; border-radius: 8px; border-left: 3px solid #f59e0b;">
                    <strong style="color: #92400e;">🔗 Link:</strong> 
                    <a href="{threat.link}" target="_blank" style="color: #1d4ed8; text-decoration: none;">
                        {threat.link[:80]}{'...' if len(threat.link) > 80 else ''}
                    </a>
                </div>
            </div>
            """
        
        if len(results) > 5:
            results_html += f"""
            <div style="text-align: center; padding: 20px; background: #f1f5f9; border-radius: 10px; border: 2px dashed #cbd5e1;">
                <span style="color: #475569; font-weight: 600;">
                    ... and {len(results) - 5} more threat intelligence matches
                </span>
            </div>
            """
        
        results_html += "</div></div>"
        return results_html
    
    def _create_error_display(self, ioc: str, error: str):
        """Create error display for IOC analysis"""
        return f"""
        <div style="background: #fef2f2; padding: 25px; border-radius: 15px; border: 1px solid #fecaca;">
            <div style="background: #dc2626; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
                <h4 style="margin: 0 0 10px 0;">❌ IOC Analysis Error</h4>
                <p style="margin: 0; opacity: 0.9;">Failed to analyze IOC: {ioc}</p>
            </div>
            <div style="background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #dc2626;">
                <strong style="color: #dc2626;">Error Details:</strong>
                <p style="margin: 8px 0 0 0; color: #7f1d1d; font-family: monospace; font-size: 0.9em;">
                    {error}
                </p>
            </div>
        </div>
        """
    
    def _get_alerts_display(self):
        """Get current alerts display"""
        if not ADVANCED_FEATURES_AVAILABLE:
            return "<div style='text-align: center; padding: 40px; color: #dc2626;'>Advanced alert system not available</div>"
        
        try:
            return self.alert_system.create_alert_dashboard_html()
        except Exception as e:
            logger.error(f"Error getting alerts display: {e}")
            return f"<div style='color: #dc2626;'>Error loading alerts: {str(e)}</div>"
    
    def _create_header(self):
        """Create the dashboard header"""
        return gr.HTML("""
        <div style="text-align: center; background: linear-gradient(135deg, #1e40af, #1d4ed8); 
                   padding: 30px; border-radius: 15px; margin-bottom: 30px; color: white;
                   box-shadow: 0 10px 30px rgba(30, 64, 175, 0.3);">
            <h1 style="margin: 0; font-size: 2.8em; font-weight: bold; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                🛡️ Ultimate Threat Intelligence Command Center
            </h1>
            <p style="margin: 15px 0 0 0; font-size: 1.3em; opacity: 0.95;">
                Advanced AI-Powered Cybersecurity Operations Center
            </p>
            <div style="margin-top: 20px; display: flex; justify-content: center; gap: 20px; flex-wrap: wrap;">
                <span style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 20px; font-size: 0.9em;">
                    🤖 AI-Enhanced
                </span>
                <span style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 20px; font-size: 0.9em;">
                    🔴 Real-time
                </span>
                <span style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 20px; font-size: 0.9em;">
                    🎯 Threat Hunting
                </span>
                <span style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 20px; font-size: 0.9em;">
                    📊 Advanced Analytics
                </span>
            </div>
        </div>
        """)
    
    def _get_professional_css(self):
        """Get professional CSS styling for the dashboard"""
        return """
        /* Ultimate SOC Dashboard Styling */
        .gradio-container {
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .gr-button {
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            border: none;
            color: white;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .gr-button:hover {
            background: linear-gradient(135deg, #1d4ed8, #1e40af);
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4);
        }
        
        .gr-textbox {
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            transition: border-color 0.3s ease;
        }
        
        .gr-textbox:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .gr-tab {
            background: white;
            border: 1px solid #e2e8f0;
            margin: 2px;
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        
        .gr-tab:hover {
            background: #f8fafc;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        """

    def launch(self, share: bool = False, server_port: int = 7860) -> None:
        """Launch the Ultimate Threat Intelligence Command Center"""
        try:
            logger.info("🚀 Launching Ultimate Threat Intelligence Command Center...")
            
            # Create the interface
            with gr.Blocks(
                css=self._get_professional_css(),
                title="🛡️ Ultimate Threat Intelligence Command Center",
                theme=gr.themes.Base()
            ) as interface:
                
                # Header
                self._create_header()
                
                # Main tabbed interface with advanced features
                with gr.Tabs() as tabs:
                    # Live Feed Tab (Enhanced)
                    with gr.Tab("🔴 Live Threat Feed", id="live-feed"):
                        with gr.Row():
                            with gr.Column(scale=3):
                                feed_output = gr.HTML(
                                    value="<div style='text-align: center; padding: 40px; color: #64748b;'>🛡️ Ultimate SOC Dashboard Ready<br><br>Click 'Start Live Feed' to begin real-time threat intelligence collection with advanced AI analysis</div>",
                                    label="Real-time Threat Stream"
                                )
                            
                            with gr.Column(scale=1):
                                gr.HTML("<h3 style='color: #1e293b; margin-bottom: 20px;'>⚡ Command Center</h3>")
                                
                                start_btn = gr.Button(
                                    "🚀 Start Live Feed",
                                    variant="primary",
                                    size="lg"
                                )
                                
                                refresh_btn = gr.Button(
                                    "🔄 Refresh Display",
                                    variant="secondary"
                                )
                                
                                hunt_btn = gr.Button(
                                    "🎯 Run Threat Hunt",
                                    variant="secondary"
                                ) if ADVANCED_FEATURES_AVAILABLE else None
                                
                                progress_display = gr.HTML(
                                    value=self._create_progress_html(0, 0, "Ultimate SOC Ready"),
                                    label="Processing Status"
                                )
                    
                    # Analytics Center (Enhanced with Visualizations)
                    with gr.Tab("📊 Advanced Analytics", id="analytics"):
                        with gr.Row():
                            with gr.Column():
                                stats_display = gr.HTML(
                                    value=self._create_stats_html(),
                                    label="Threat Intelligence Statistics"
                                )
                            
                        if ADVANCED_FEATURES_AVAILABLE:
                            with gr.Row():
                                with gr.Column():
                                    threat_map_btn = gr.Button("🌍 Generate Threat Map", variant="primary")
                                    threat_map_display = gr.HTML(
                                        value="<div style='text-align: center; padding: 40px; color: #64748b;'>Click 'Generate Threat Map' to create interactive global threat visualization</div>"
                                    )
                                
                                with gr.Column():
                                    timeline_btn = gr.Button("� Generate Timeline", variant="primary")
                                    timeline_display = gr.HTML(
                                        value="<div style='text-align: center; padding: 40px; color: #64748b;'>Click 'Generate Timeline' to create threat timeline analysis</div>"
                                    )
                    
                    # Live Alert System Tab
                    if ADVANCED_FEATURES_AVAILABLE:
                        with gr.Tab("🚨 Live Alerts", id="alerts"):
                            with gr.Row():
                                alert_display = gr.HTML(
                                    value=self.alert_system.create_alert_dashboard_html(),
                                    label="Live Alert Dashboard"
                                )
                            
                            with gr.Row():
                                alert_refresh_btn = gr.Button("🔄 Refresh Alerts", variant="secondary")
                    
                    # AI Chat Assistant Tab
                    if ADVANCED_FEATURES_AVAILABLE:
                        with gr.Tab("🤖 AI Security Assistant", id="ai-chat"):
                            gr.HTML("<h2 style='color: #1e293b;'>🤖 Advanced AI Security Assistant</h2>")
                            
                            with gr.Row():
                                with gr.Column():
                                    chat_input = gr.Textbox(
                                        label="Ask the AI Security Expert",
                                        placeholder="Ask about threats, APTs, ransomware, IOCs, security best practices...",
                                        lines=3
                                    )
                                    
                                    # Suggested questions
                                    with gr.Row():
                                        suggest_apt_btn = gr.Button("APT Trends", size="sm")
                                        suggest_ransomware_btn = gr.Button("Ransomware Defense", size="sm") 
                                        suggest_ioc_btn = gr.Button("IOC Analysis", size="sm")
                                        suggest_mitre_btn = gr.Button("MITRE ATT&CK", size="sm")
                                    
                                    chat_submit_btn = gr.Button("🧠 Ask AI Expert", variant="primary")
                                
                                with gr.Column():
                                    chat_output = gr.HTML(
                                        value="<div style='text-align: center; padding: 40px; color: #64748b;'>Ask the AI security expert any cybersecurity question</div>"
                                    )
                    
                    # Automated Threat Hunting Tab
                    if ADVANCED_FEATURES_AVAILABLE:
                        with gr.Tab("🎯 Threat Hunting", id="hunting"):
                            gr.HTML("<h2 style='color: #1e293b;'>🎯 Automated Threat Hunting Center</h2>")
                            
                            with gr.Row():
                                with gr.Column():
                                    hunt_run_btn = gr.Button("🚀 Run Full Hunt", variant="primary", size="lg")
                                    hunt_status = gr.HTML(
                                        value="<div style='text-align: center; padding: 20px; color: #64748b;'>Ready to run automated threat hunting</div>"
                                    )
                                
                                with gr.Column():
                                    hunt_results = gr.HTML(
                                        value="<div style='text-align: center; padding: 40px; color: #64748b;'>Click 'Run Full Hunt' to execute automated threat hunting across all intelligence</div>"
                                    )
                    
                    # IOC Intelligence Tab (Enhanced)
                    with gr.Tab("🔍 IOC Intelligence", id="ioc-intel"):
                        gr.HTML("<h2 style='color: #1e293b;'>🔍 Advanced IOC Analysis & Intelligence</h2>")
                        
                        with gr.Row():
                            with gr.Column():
                                ioc_search = gr.Textbox(
                                    label="Search IOCs",
                                    placeholder="Enter IP, domain, hash, or other IOC...",
                                    lines=2
                                )
                                search_btn = gr.Button("🔍 Search IOCs", variant="primary")
                                
                                if ADVANCED_FEATURES_AVAILABLE:
                                    bulk_ioc_input = gr.File(
                                        label="Upload IOC List (CSV/TXT)",
                                        file_types=[".csv", ".txt"]
                                    )
                                    bulk_analyze_btn = gr.Button("📊 Bulk IOC Analysis", variant="secondary")
                            
                            with gr.Column():
                                ioc_results = gr.HTML(
                                    value="<div style='text-align: center; padding: 20px; color: #64748b;'>Enter an IOC to search the threat intelligence database</div>"
                                )
                
                # Event handlers for basic functionality
                start_btn.click(
                    fn=self._start_live_feed,
                    outputs=[feed_output, progress_display, stats_display]
                )
                
                refresh_btn.click(
                    fn=lambda: (
                        self._create_threat_stream_html(self.aggregator.db.get_recent_threats(limit=20)),
                        self._create_stats_html()
                    ),
                    outputs=[feed_output, stats_display]
                )
                
                # Advanced feature event handlers
                if ADVANCED_FEATURES_AVAILABLE:
                    # Threat hunting
                    if hunt_btn:
                        hunt_btn.click(
                            fn=self._run_threat_hunt,
                            outputs=[feed_output, progress_display]
                        )
                    
                    # Visualization handlers
                    threat_map_btn.click(
                        fn=self._generate_threat_map,
                        outputs=[threat_map_display]
                    )
                    
                    timeline_btn.click(
                        fn=self._generate_timeline,
                        outputs=[timeline_display]
                    )
                    
                    # Alert system handlers
                    alert_refresh_btn.click(
                        fn=lambda: self.alert_system.create_alert_dashboard_html(),
                        outputs=[alert_display]
                    )
                    
                    # AI Chat handlers
                    chat_submit_btn.click(
                        fn=self._handle_chat_query,
                        inputs=[chat_input],
                        outputs=[chat_output]
                    )
                    
                    # Suggested question handlers
                    suggest_apt_btn.click(
                        fn=lambda: self._handle_chat_query("What are the latest APT trends and how can I detect them?"),
                        outputs=[chat_output]
                    )
                    
                    suggest_ransomware_btn.click(
                        fn=lambda: self._handle_chat_query("How can I defend against ransomware attacks?"),
                        outputs=[chat_output]
                    )
                    
                    suggest_ioc_btn.click(
                        fn=lambda: self._handle_chat_query("Explain IOC analysis and what IOCs should I monitor?"),
                        outputs=[chat_output]
                    )
                    
                    suggest_mitre_btn.click(
                        fn=lambda: self._handle_chat_query("Explain the MITRE ATT&CK framework and how to use it"),
                        outputs=[chat_output]
                    )
                    
                    # Threat hunting handlers
                    hunt_run_btn.click(
                        fn=self._run_automated_hunt,
                        outputs=[hunt_results, hunt_status]
                    )
            
            # Launch interface
            interface.launch(
                share=share,
                server_port=server_port,
                server_name="0.0.0.0" if share else "127.0.0.1",
                show_error=True,
                quiet=False
            )
            
        except Exception as e:
            logger.error(f"Failed to launch dashboard: {e}")
            raise

# Update class name for compatibility
ThreatIntelDashboard = RealTimeThreatDashboard
