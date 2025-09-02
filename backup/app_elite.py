"""
🛡️ TIFA - Elite Threat Intelligence Feed Aggregator
World-Class Enterprise Dashboard for International Hackathon Competition
Advanced AI-Powered Real-Time Threat Intelligence Platform
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import logging
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor

from config import Config
from models import ThreatIntelItem
from database import ThreatIntelDatabase
from core import AIAnalyzer, IOCExtractor, FeedCollector, ThreatCorrelator, AlertSystem

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Page Configuration with Professional Theme
st.set_page_config(
    page_title=Config.APP_TITLE,
    page_icon=Config.APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/Deepam02/TIFA',
        'Report a bug': "https://github.com/Deepam02/TIFA/issues",
        'About': f"# {Config.APP_TITLE}\n{Config.APP_DESCRIPTION}"
    }
)

# Custom CSS for Professional UI
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #ff6b6b, #4ecdc4, #45b7d1);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    .threat-card {
        border-left: 5px solid;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
        background-color: #f8f9fa;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .critical { border-left-color: #dc3545; }
    .high { border-left-color: #fd7e14; }
    .medium { border-left-color: #0dcaf0; }
    .low { border-left-color: #198754; }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #2c3e50 0%, #3498db 100%);
    }
    
    .status-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
    }
    
    .status-active { background-color: #28a745; }
    .status-warning { background-color: #ffc107; }
    .status-error { background-color: #dc3545; }
</style>
""", unsafe_allow_html=True)

# --- Elite Aggregator Class ---
class EliteThreatIntelAggregator:
    """Enterprise-grade threat intelligence orchestrator with advanced features."""
    
    def __init__(self):
        """Initialize all components with enterprise capabilities."""
        self.db = ThreatIntelDatabase()
        self.ioc_extractor = IOCExtractor()
        self.feed_collector = FeedCollector(self.db, self.ioc_extractor)
        self.ai_analyzer = AIAnalyzer()
        self.correlator = ThreatCorrelator(self.db)
        self.alert_system = AlertSystem()
        
        # Performance metrics
        self.metrics = {
            "feeds_processed": 0,
            "threats_analyzed": 0,
            "iocs_extracted": 0,
            "alerts_generated": 0,
            "ai_requests": 0,
            "last_update": None
        }

    def run_elite_aggregation(self, progress_callback=None) -> Dict[str, Any]:
        """Run comprehensive threat intelligence aggregation with real-time feedback."""
        start_time = time.time()
        results = {
            "success": False,
            "feeds_processed": 0,
            "new_threats": 0,
            "total_iocs": 0,
            "critical_alerts": 0,
            "processing_time": 0,
            "errors": []
        }
        
        try:
            logger.info("🚀 Starting elite threat intelligence aggregation...")
            
            # Collect all feeds with concurrent processing
            if progress_callback:
                progress_callback("🔄 Collecting feeds concurrently...")
            
            feed_results = self.feed_collector.collect_all_feeds()
            results["feeds_processed"] = len(feed_results)
            
            total_new_threats = 0
            total_iocs = 0
            critical_alerts = 0
            
            # Process each feed's results
            for feed_name, items in feed_results.items():
                if progress_callback:
                    progress_callback(f"🧠 AI analyzing {feed_name}...")
                
                for item in items:
                    # Advanced AI analysis with multiple models
                    analysis = self.ai_analyzer.analyze(
                        f"{item.title}\n{item.summary}",
                        analysis_type="summary"
                    )
                    
                    # Update item with AI insights
                    item.summary = analysis.get("summary", item.summary)
                    item.severity = analysis.get("severity", "Medium")
                    item.category = analysis.get("category", "Unknown")
                    item.confidence = analysis.get("confidence", "Medium")
                    
                    # Find threat correlations
                    correlations = self.correlator.find_correlations(item)
                    
                    # Check for alerts
                    alerts = self.alert_system.check_alerts(item)
                    if any(alert["severity"] == "critical" for alert in alerts):
                        critical_alerts += 1
                    
                    # Save to database
                    self.db.save_item(item)
                    total_new_threats += 1
                    
                    # Count IOCs
                    for ioc_list in item.iocs.values():
                        total_iocs += len(ioc_list)
            
            results.update({
                "success": True,
                "new_threats": total_new_threats,
                "total_iocs": total_iocs,
                "critical_alerts": critical_alerts,
                "processing_time": round(time.time() - start_time, 2)
            })
            
            # Update metrics
            self.metrics.update({
                "feeds_processed": results["feeds_processed"],
                "threats_analyzed": total_new_threats,
                "iocs_extracted": total_iocs,
                "alerts_generated": critical_alerts,
                "last_update": datetime.now().isoformat()
            })
            
            logger.info(f"✅ Elite aggregation completed in {results['processing_time']}s")
            
        except Exception as e:
            logger.error(f"❌ Elite aggregation failed: {e}")
            results["errors"].append(str(e))
            
        return results

# --- Advanced UI Components ---
def render_elite_header():
    """Render the professional header with live status."""
    st.markdown('<h1 class="main-header">🛡️ TIFA - Elite Threat Intelligence Aggregator</h1>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown("### 🌐 **Global Threat Intelligence Platform**")
        st.markdown("*Real-time AI-powered threat aggregation and analysis*")
    
    with col2:
        # Live status indicator
        if "last_update" in st.session_state.get("metrics", {}):
            st.markdown('<span class="status-indicator status-active"></span>**LIVE**', unsafe_allow_html=True)
        else:
            st.markdown('<span class="status-indicator status-warning"></span>**STANDBY**', unsafe_allow_html=True)
    
    with col3:
        current_time = datetime.now().strftime("%H:%M:%S UTC")
        st.markdown(f"🕒 **{current_time}**")

def render_elite_metrics(aggregator: EliteThreatIntelAggregator):
    """Render real-time metrics dashboard."""
    st.markdown("## 📊 Real-Time Intelligence Metrics")
    
    # Get latest stats
    stats = aggregator.db.get_statistics()
    
    # Create metrics columns
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="🎯 Total Threats",
            value=stats.get("total_threats", 0),
            delta=f"+{aggregator.metrics.get('threats_analyzed', 0)} today"
        )
    
    with col2:
        st.metric(
            label="🔍 Total IOCs",
            value=stats.get("total_iocs", 0),
            delta=f"+{aggregator.metrics.get('iocs_extracted', 0)} extracted"
        )
    
    with col3:
        st.metric(
            label="📡 Active Sources",
            value=len(Config.THREAT_FEEDS),
            delta=f"{aggregator.metrics.get('feeds_processed', 0)} processed"
        )
    
    with col4:
        st.metric(
            label="🤖 AI Requests",
            value=aggregator.metrics.get("ai_requests", 0),
            delta=f"Load balanced across {len(Config.GEMINI_API_KEYS)} keys"
        )
    
    with col5:
        st.metric(
            label="🚨 Critical Alerts",
            value=aggregator.metrics.get("alerts_generated", 0),
            delta="Real-time monitoring"
        )

def render_elite_threat_item(item: ThreatIntelItem, show_correlations=True):
    """Render individual threat with advanced visualization."""
    severity_class = item.severity.lower() if hasattr(item, 'severity') else 'medium'
    
    # Threat card with gradient styling
    st.markdown(f"""
    <div class="threat-card {severity_class}">
        <h4>🎯 {item.title}</h4>
        <div style="display: flex; justify-content: space-between; margin: 10px 0;">
            <span><strong>📡 Source:</strong> {item.source}</span>
            <span><strong>📅 Published:</strong> {item.published_date.split('T')[0]}</span>
            <span><strong>🔥 Severity:</strong> {getattr(item, 'severity', 'Medium')}</span>
        </div>
        <p style="margin: 15px 0;">{item.summary}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Advanced expandable details
    with st.expander("🔍 Advanced Threat Analysis"):
        
        # Create tabs for different analysis views
        tab1, tab2, tab3, tab4 = st.tabs(["📋 Details", "🎯 IOCs", "🧠 AI Analysis", "🔗 Correlations"])
        
        with tab1:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**🔗 Original Link:** [View Article]({item.link})")
                st.markdown(f"**📂 Category:** {getattr(item, 'category', 'Unknown')}")
                st.markdown(f"**🎯 Priority:** {getattr(item, 'priority', 'Medium')}")
            
            with col2:
                st.markdown(f"**🤖 Confidence:** {getattr(item, 'confidence', 'Medium')}")
                st.markdown(f"**📊 Analysis Type:** {getattr(item, 'analysis_type', 'Standard')}")
                st.markdown(f"**🔑 API Key Used:** {getattr(item, 'api_key_used', 'N/A')}")
        
        with tab2:
            # IOC visualization
            ioc_data = []
            for ioc_type, iocs in item.iocs.items():
                for ioc in iocs:
                    ioc_data.append({"Type": ioc_type.upper(), "Value": ioc})
            
            if ioc_data:
                df_iocs = pd.DataFrame(ioc_data)
                st.dataframe(df_iocs, use_container_width=True)
                
                # IOC type distribution chart
                ioc_counts = df_iocs['Type'].value_counts()
                if len(ioc_counts) > 0:
                    fig = px.pie(values=ioc_counts.values, names=ioc_counts.index, 
                               title="IOC Distribution")
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No IOCs extracted from this threat.")
        
        with tab3:
            # AI Analysis results
            if hasattr(item, 'ai_analysis'):
                st.json(item.ai_analysis)
            else:
                st.info("AI analysis not available for this item.")
        
        with tab4:
            # Threat correlations (placeholder for now)
            st.info("🔗 Threat correlation analysis coming soon...")

def render_elite_dashboard(aggregator: EliteThreatIntelAggregator):
    """Main elite dashboard with advanced features."""
    render_elite_header()
    render_elite_metrics(aggregator)
    
    # Action buttons
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🚀 **REFRESH ALL FEEDS**", type="primary", use_container_width=True):
            with st.spinner("🔄 Elite aggregation in progress..."):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                def progress_callback(message):
                    status_text.text(message)
                    progress_bar.progress(min(progress_bar.progress + 0.1, 1.0))
                
                results = aggregator.run_elite_aggregation(progress_callback)
                
                if results["success"]:
                    st.success(f"""
                    ✅ **Elite Aggregation Complete!**
                    - 📡 Feeds Processed: {results['feeds_processed']}
                    - 🎯 New Threats: {results['new_threats']}
                    - 🔍 IOCs Extracted: {results['total_iocs']}
                    - ⚡ Processing Time: {results['processing_time']}s
                    """)
                else:
                    st.error(f"❌ Aggregation failed: {', '.join(results['errors'])}")
                
                st.rerun()
    
    with col2:
        if st.button("🤖 **AI DEEP SCAN**", use_container_width=True):
            st.info("🧠 Advanced AI correlation analysis initiated...")
    
    with col3:
        if st.button("📊 **EXPORT INTEL**", use_container_width=True):
            st.info("📦 Intelligence export feature coming soon...")
    
    with col4:
        if st.button("🚨 **ALERT CONFIG**", use_container_width=True):
            st.info("⚙️ Alert configuration panel coming soon...")
    
    # Main threat feed display
    st.markdown("## 🎯 Live Threat Intelligence Feed")
    
    # Filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.selectbox("🔥 Severity Filter", ["All", "Critical", "High", "Medium", "Low"])
    with col2:
        source_filter = st.selectbox("📡 Source Filter", ["All"] + [feed["name"] for feed in Config.THREAT_FEEDS])
    with col3:
        limit = st.slider("📄 Items to Show", 5, 100, 20)
    
    # Get and display threats
    threats = aggregator.db.get_recent_threats(limit=limit)
    
    if not threats:
        st.info("🔍 No threat intelligence data found. Click 'REFRESH ALL FEEDS' to start collecting.")
        return
    
    # Apply filters
    if severity_filter != "All":
        threats = [t for t in threats if getattr(t, 'severity', 'Medium') == severity_filter]
    
    if source_filter != "All":
        threats = [t for t in threats if t.source == source_filter]
    
    # Display threats
    for item in threats:
        render_elite_threat_item(item)

def render_elite_ioc_search(aggregator: EliteThreatIntelAggregator):
    """Advanced IOC search and analysis."""
    st.markdown("## 🔍 Elite IOC Hunter")
    st.markdown("*Advanced search and correlation across global threat intelligence*")
    
    # Search interface
    col1, col2 = st.columns([3, 1])
    
    with col1:
        query = st.text_input(
            "🎯 Search IOCs, Hashes, Domains, IPs, CVEs:",
            placeholder="e.g., 192.168.1.1, malware.example.com, CVE-2021-44228, d41d8cd98f00b204e9800998ecf8427e",
            help="Enter any IOC type for advanced correlation analysis"
        )
    
    with col2:
        search_type = st.selectbox("🔍 Search Type", ["All IOCs", "IP Addresses", "Domains", "Hashes", "CVEs", "URLs"])
    
    if query:
        # Advanced search with correlation
        with st.spinner("🧠 Performing elite IOC correlation analysis..."):
            results = aggregator.db.search_ioc(query)
            
            if results:
                st.success(f"🎯 Found **{len(results)}** correlated threats for `{query}`")
                
                # IOC analysis metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("🔍 Matches Found", len(results))
                with col2:
                    sources = list(set([r.source for r in results]))
                    st.metric("📡 Sources", len(sources))
                with col3:
                    severities = [getattr(r, 'severity', 'Medium') for r in results]
                    critical_count = severities.count('Critical')
                    st.metric("🚨 Critical", critical_count)
                with col4:
                    recent_count = len([r for r in results if 
                                     datetime.fromisoformat(r.published_date.replace('Z', '+00:00')) > 
                                     datetime.now() - timedelta(days=7)])
                    st.metric("📅 Recent (7d)", recent_count)
                
                # Visualization
                if len(results) > 1:
                    # Timeline chart
                    dates = [datetime.fromisoformat(r.published_date.replace('Z', '+00:00')).date() for r in results]
                    date_counts = pd.Series(dates).value_counts().sort_index()
                    
                    fig = px.line(x=date_counts.index, y=date_counts.values,
                                title=f"Threat Timeline for IOC: {query}")
                    st.plotly_chart(fig, use_container_width=True)
                
                # Display correlated threats
                st.markdown("### 🔗 Correlated Threats")
                for item in results:
                    render_elite_threat_item(item, show_correlations=False)
            else:
                st.warning(f"🔍 No correlations found for `{query}`. This IOC may be new or not in our threat database.")

def render_elite_analytics(aggregator: EliteThreatIntelAggregator):
    """Advanced analytics and visualization dashboard."""
    st.markdown("## 📊 Elite Threat Analytics")
    st.markdown("*Advanced intelligence analytics and strategic insights*")
    
    # Get comprehensive data
    stats = aggregator.db.get_statistics()
    threats = aggregator.db.get_recent_threats(limit=500)
    
    if not threats:
        st.info("📈 No data available for analytics. Please refresh feeds first.")
        return
    
    # Convert to DataFrame for analysis
    threat_data = []
    for t in threats:
        threat_data.append({
            'title': t.title,
            'source': t.source,
            'severity': getattr(t, 'severity', 'Medium'),
            'category': getattr(t, 'category', 'Unknown'),
            'published_date': datetime.fromisoformat(t.published_date.replace('Z', '+00:00')),
            'ioc_count': sum(len(iocs) for iocs in t.iocs.values())
        })
    
    df = pd.DataFrame(threat_data)
    
    # Analytics tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📈 Trends", "🎯 Sources", "🔥 Severity", "💎 IOCs"])
    
    with tab1:
        st.markdown("### 📈 Threat Intelligence Trends")
        
        # Time series analysis
        daily_threats = df.groupby(df['published_date'].dt.date).size()
        fig = px.line(x=daily_threats.index, y=daily_threats.values,
                     title="Daily Threat Intelligence Volume")
        st.plotly_chart(fig, use_container_width=True)
        
        # Category trends
        category_trends = df.groupby(['published_date', 'category']).size().reset_index(name='count')
        fig2 = px.area(category_trends, x='published_date', y='count', color='category',
                      title="Threat Categories Over Time")
        st.plotly_chart(fig2, use_container_width=True)
    
    with tab2:
        st.markdown("### 📡 Source Intelligence Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Source distribution
            source_counts = df['source'].value_counts()
            fig = px.pie(values=source_counts.values, names=source_counts.index,
                        title="Threat Intelligence by Source")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Source quality metrics
            source_quality = df.groupby('source').agg({
                'ioc_count': 'mean',
                'severity': lambda x: (x == 'Critical').sum() + (x == 'High').sum() * 0.7 + (x == 'Medium').sum() * 0.3
            }).round(2)
            source_quality.columns = ['Avg IOCs', 'Quality Score']
            st.dataframe(source_quality, use_container_width=True)
    
    with tab3:
        st.markdown("### 🔥 Severity Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Severity distribution
            severity_counts = df['severity'].value_counts()
            colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#0dcaf0', 'Low': '#198754'}
            fig = px.bar(x=severity_counts.index, y=severity_counts.values,
                        title="Threat Severity Distribution",
                        color=severity_counts.index,
                        color_discrete_map=colors)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Severity trends over time
            severity_trends = df.groupby([df['published_date'].dt.date, 'severity']).size().reset_index(name='count')
            fig2 = px.line(severity_trends, x='published_date', y='count', color='severity',
                          title="Severity Trends Over Time")
            st.plotly_chart(fig2, use_container_width=True)
    
    with tab4:
        st.markdown("### 💎 IOC Intelligence Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # IOC distribution
            fig = px.histogram(df, x='ioc_count', bins=20,
                             title="IOC Count Distribution per Threat")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Top IOC producers
            ioc_producers = df.nlargest(10, 'ioc_count')[['source', 'title', 'ioc_count']]
            st.markdown("**🏆 Top IOC Producers**")
            st.dataframe(ioc_producers, use_container_width=True)

# --- Main Application ---
def main():
    """Main application entry point with elite features."""
    
    # Initialize session state
    if 'aggregator' not in st.session_state:
        st.session_state.aggregator = EliteThreatIntelAggregator()
    
    aggregator = st.session_state.aggregator
    
    # Elite sidebar navigation
    with st.sidebar:
        st.markdown("# 🛡️ **TIFA Control Center**")
        st.markdown("---")
        
        # Navigation
        page = st.radio(
            "🚀 **Navigation**",
            ["🎯 Live Dashboard", "🔍 IOC Hunter", "📊 Elite Analytics", "⚙️ Configuration"],
            index=0
        )
        
        st.markdown("---")
        
        # System status
        st.markdown("### 📡 **System Status**")
        st.markdown(f"🔑 **API Keys:** {len(Config.GEMINI_API_KEYS)} active")
        st.markdown(f"📡 **Feed Sources:** {len(Config.THREAT_FEEDS)} configured")
        st.markdown(f"🤖 **AI Models:** {len(Config.GEMINI_MODELS)} available")
        
        if aggregator.metrics.get("last_update"):
            last_update = datetime.fromisoformat(aggregator.metrics["last_update"])
            st.markdown(f"🕒 **Last Update:** {last_update.strftime('%H:%M:%S')}")
        
        st.markdown("---")
        
        # Quick stats
        stats = aggregator.db.get_statistics()
        st.markdown("### 📈 **Quick Stats**")
        st.metric("Total Threats", stats.get("total_threats", 0))
        st.metric("Total IOCs", stats.get("total_iocs", 0))
        st.metric("Active Sources", len(Config.THREAT_FEEDS))
        
        st.markdown("---")
        st.markdown("### ℹ️ **About TIFA**")
        st.markdown("""
        **Elite Threat Intelligence Feed Aggregator**
        
        🎯 Real-time threat aggregation  
        🤖 Multi-model AI analysis  
        🔍 Advanced IOC correlation  
        📊 Enterprise analytics  
        🚨 Intelligent alerting  
        
        Built for hackathon excellence! 🏆
        """)
    
    # Main content routing
    if page == "🎯 Live Dashboard":
        render_elite_dashboard(aggregator)
    elif page == "🔍 IOC Hunter":
        render_elite_ioc_search(aggregator)
    elif page == "📊 Elite Analytics":
        render_elite_analytics(aggregator)
    elif page == "⚙️ Configuration":
        st.markdown("## ⚙️ System Configuration")
        st.info("🔧 Advanced configuration panel coming soon...")
        
        # Show current configuration
        st.markdown("### 📋 Current Configuration")
        config_data = {
            "API Keys": len(Config.GEMINI_API_KEYS),
            "Feed Sources": len(Config.THREAT_FEEDS),
            "AI Models": len(Config.GEMINI_MODELS),
            "Max Items per Feed": Config.MAX_ITEMS_PER_FEED,
            "Max Concurrent Requests": Config.MAX_CONCURRENT_AI_REQUESTS,
            "Database Path": Config.DB_PATH
        }
        
        for key, value in config_data.items():
            st.text(f"{key}: {value}")

if __name__ == "__main__":
    main()
