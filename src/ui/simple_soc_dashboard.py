"""
Simple SOC-Focused Threat Intelligence Dashboard
Core functionality for monitoring, summarization, and analysis
"""
import streamlit as st
import pandas as pd
import time
import json
import threading
from datetime import datetime
from typing import List, Dict, Any

# Import our modules
from config import Config
from models import ThreatIntelItem
from database import ThreatIntelDatabase
from core import IOCExtractor, AIAnalyzer, FeedCollector

# --- Configuration ---
st.set_page_config(
    page_title="SOC Threat Intel Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for SOC Teams ---
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .threat-card {
        background: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 4px solid #007bff;
    }
    
    .threat-card.critical {
        border-left-color: #dc3545;
        background: #fff5f5;
    }
    
    .threat-card.high {
        border-left-color: #fd7e14;
        background: #fff8f0;
    }
    
    .threat-card.medium {
        border-left-color: #ffc107;
        background: #fffdf0;
    }
    
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
    
    .ioc-table {
        background: white;
        border-radius: 8px;
        padding: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# --- Core Dashboard Class ---
class SOCDashboard:
    """Simple dashboard focused on core SOC functionality."""
    
    def __init__(self):
        """Initialize dashboard components."""
        self.db = ThreatIntelDatabase()
        self.ioc_extractor = IOCExtractor()
        self.ai_analyzer = AIAnalyzer()
        self.feed_collector = FeedCollector(self.db, self.ioc_extractor)
        
        # Initialize session state
        if 'last_refresh' not in st.session_state:
            st.session_state.last_refresh = None
        if 'aggregation_running' not in st.session_state:
            st.session_state.aggregation_running = False

    def render_header(self):
        """Render dashboard header."""
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ SOC Threat Intelligence Dashboard</h1>
            <p>Real-time monitoring • Threat summarization • IOC analysis</p>
        </div>
        """, unsafe_allow_html=True)

    def render_metrics(self):
        """Render key metrics for SOC teams."""
        threats = self.db.get_recent_threats(limit=1000)
        stats = self.db.get_statistics()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>📊 Total Threats</h3>
                <h2 style="color: #007bff;">{}</h2>
            </div>
            """.format(stats.get('total_threats', 0)), unsafe_allow_html=True)
        
        with col2:
            critical_count = len([t for t in threats if getattr(t, 'severity', 'Medium') == 'Critical'])
            st.markdown("""
            <div class="metric-card">
                <h3>🚨 Critical</h3>
                <h2 style="color: #dc3545;">{}</h2>
            </div>
            """.format(critical_count), unsafe_allow_html=True)
        
        with col3:
            total_iocs = sum(len(list(t.iocs.values())[0]) if t.iocs else 0 for t in threats[:100])
            st.markdown("""
            <div class="metric-card">
                <h3>🎯 IOCs</h3>
                <h2 style="color: #28a745;">{}</h2>
            </div>
            """.format(total_iocs), unsafe_allow_html=True)
        
        with col4:
            sources_count = len(set(t.source for t in threats[:100]))
            st.markdown("""
            <div class="metric-card">
                <h3>📡 Sources</h3>
                <h2 style="color: #6610f2;">{}</h2>
            </div>
            """.format(sources_count), unsafe_allow_html=True)

    def render_controls(self):
        """Render simple control panel."""
        st.subheader("🎛️ Control Panel")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🔄 Refresh Feeds", type="primary", use_container_width=True):
                self.start_background_collection()
        
        with col2:
            auto_refresh = st.checkbox("⚡ Auto-refresh (30s)", key="auto_refresh")
            if auto_refresh:
                time.sleep(30)
                st.rerun()
        
        with col3:
            if st.button("📊 Generate Report", use_container_width=True):
                self.generate_threat_report()

    def start_background_collection(self):
        """Start background threat collection."""
        if not st.session_state.aggregation_running:
            st.session_state.aggregation_running = True
            st.session_state.aggregation_start = time.time()
            
            st.success("🚀 Background collection started!")
            
            def collect_threats():
                try:
                    # Process top 5 reliable sources
                    reliable_feeds = [
                        {"name": "🎯 SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml"},
                        {"name": "🏛️ US-CERT CISA", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
                        {"name": "🔬 Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
                        {"name": "🔬 BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
                        {"name": "🕵️ HackerNews", "url": "https://thehackernews.com/feeds/posts/default"}
                    ]
                    
                    for feed in reliable_feeds:
                        items = self.feed_collector.fetch_feed(feed)
                        if items:
                            for item in items[:3]:  # Limit to 3 per feed
                                if not self.db.item_exists(item.id):
                                    # Quick AI analysis
                                    analysis = self.ai_analyzer.analyze(f"{item.title}\\n{item.summary}")
                                    item.category = analysis.get("category", "unknown")
                                    item.severity = analysis.get("severity", "Medium")
                                    self.db.save_item(item)
                    
                    st.session_state.aggregation_running = False
                    st.session_state.last_refresh = datetime.now()
                    
                except Exception as e:
                    st.session_state.aggregation_running = False
                    st.error(f"Collection failed: {e}")
            
            # Start background thread
            thread = threading.Thread(target=collect_threats, daemon=True)
            thread.start()
            
            st.rerun()
        else:
            st.warning("Collection already in progress...")

    def render_threat_feed(self):
        """Render live threat feed."""
        st.subheader("🔴 Live Threat Feed")
        
        # Status indicator
        if st.session_state.aggregation_running:
            elapsed = time.time() - st.session_state.get('aggregation_start', time.time())
            st.info(f"🔄 Collection active ({elapsed:.0f}s) - New threats will appear automatically")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            severity_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])
        with col2:
            category_filter = st.selectbox("Category", ["All", "malware", "phishing", "vulnerability", "apt", "unknown"])
        with col3:
            limit = st.slider("Show", 5, 50, 20)
        
        # Get threats
        threats = self.db.get_recent_threats(limit=limit)
        
        # Apply filters
        if severity_filter != "All":
            threats = [t for t in threats if getattr(t, 'severity', 'Medium') == severity_filter]
        if category_filter != "All":
            threats = [t for t in threats if getattr(t, 'category', 'unknown') == category_filter]
        
        # Display threats
        if threats:
            for i, threat in enumerate(threats):
                self.render_threat_card(threat, i)
        else:
            st.info("No threats found. Click 'Refresh Feeds' to collect data.")

    def render_threat_card(self, threat: ThreatIntelItem, index: int):
        """Render individual threat card."""
        severity = getattr(threat, 'severity', 'Medium').lower()
        category = getattr(threat, 'category', 'unknown')
        
        # Threat card
        st.markdown(f"""
        <div class="threat-card {severity}">
            <h4>🎯 {threat.title}</h4>
            <div style="display: flex; justify-content: space-between; margin: 10px 0;">
                <span><strong>📡 Source:</strong> {threat.source}</span>
                <span><strong>📂 Category:</strong> {category.title()}</span>
                <span><strong>🔥 Severity:</strong> {getattr(threat, 'severity', 'Medium')}</span>
            </div>
            <p>{threat.summary[:200]}...</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Expandable details
        with st.expander(f"🔍 Threat Analysis #{index+1}"):
            
            # IOC Analysis
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**📊 IOC Analysis**")
                if threat.iocs:
                    ioc_data = []
                    for category, iocs in threat.iocs.items():
                        for ioc in list(iocs)[:5]:  # Limit to 5 per category
                            ioc_data.append({"Category": category.title(), "IOC": ioc})
                    
                    if ioc_data:
                        df = pd.DataFrame(ioc_data)
                        st.dataframe(df, use_container_width=True, hide_index=True)
                    else:
                        st.info("No IOCs extracted")
                else:
                    st.info("No IOCs available")
            
            with col2:
                st.markdown("**🔗 Threat Details**")
                st.markdown(f"**Link:** [Original Article]({threat.link})")
                st.markdown(f"**Published:** {threat.published_date.split('T')[0] if threat.published_date else 'Unknown'}")
                st.markdown(f"**Collected:** {threat.created_at.split('T')[0] if threat.created_at else 'Unknown'}")

    def render_ioc_search(self):
        """Render IOC search functionality."""
        st.subheader("🔍 IOC Search & Analysis")
        
        # Search input
        search_query = st.text_input("Search IOCs (IP, domain, hash, etc.)")
        
        if search_query:
            # Search threats containing the IOC
            matching_threats = []
            all_threats = self.db.get_recent_threats(limit=500)
            
            for threat in all_threats:
                for ioc_category, iocs in threat.iocs.items():
                    if any(search_query.lower() in ioc.lower() for ioc in iocs):
                        matching_threats.append(threat)
                        break
            
            if matching_threats:
                st.success(f"Found {len(matching_threats)} threats containing '{search_query}'")
                
                for threat in matching_threats[:10]:  # Show top 10
                    with st.expander(f"🎯 {threat.title[:50]}..."):
                        st.markdown(f"**Source:** {threat.source}")
                        st.markdown(f"**Category:** {getattr(threat, 'category', 'Unknown')}")
                        st.markdown(f"**Summary:** {threat.summary[:300]}...")
            else:
                st.warning(f"No threats found containing '{search_query}'")

    def generate_threat_report(self):
        """Generate comprehensive threat report."""
        st.subheader("📄 Threat Intelligence Report")
        
        # Get recent threats
        threats = self.db.get_recent_threats(limit=100)
        
        if not threats:
            st.warning("No threats available for reporting")
            return
        
        # Generate report using AI analyzer
        report = self.ai_analyzer.get_threat_summary_report(threats)
        
        # Display report
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📊 Threat Overview")
            st.json({
                "Total Threats": report["total_threats"],
                "Critical Threats": report["critical_threats"],
                "Top Categories": dict(report["top_categories"][:3])
            })
        
        with col2:
            st.markdown("### 🎯 Recommendations")
            for rec in report["recommendations"]:
                st.markdown(f"- {rec}")
        
        # Export option
        if st.button("📥 Export Report (JSON)"):
            report_json = json.dumps(report, indent=2)
            st.download_button(
                label="Download Report",
                data=report_json,
                file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

    def run(self):
        """Main dashboard execution."""
        # Header
        self.render_header()
        
        # Sidebar controls
        with st.sidebar:
            st.markdown("### 🎛️ Dashboard Controls")
            
            # API Key input
            api_key = st.text_input("Gemini API Key (optional)", type="password")
            if api_key:
                Config.GEMINI_API_KEYS = [api_key]
                st.success("✅ API key configured")
            
            st.markdown("---")
            
            # Dashboard sections
            section = st.radio("Navigate", [
                "🔴 Live Feed",
                "🔍 IOC Search", 
                "📊 Reports"
            ])
        
        # Main content area
        if section == "🔴 Live Feed":
            self.render_metrics()
            self.render_controls()
            self.render_threat_feed()
            
        elif section == "🔍 IOC Search":
            self.render_ioc_search()
            
        elif section == "📊 Reports":
            self.generate_threat_report()

# --- Main Application ---
def main():
    """Main application entry point."""
    dashboard = SOCDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()
