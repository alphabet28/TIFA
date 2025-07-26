"""
🛡️ TIFA - Performance Optimized Version
Fast-loading with fallback data and resilient error handling
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import logging
import time
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page Configuration
st.set_page_config(
    page_title="🛡️ TIFA - Elite Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS for better performance (simplified)
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        color: #2c3e50;
        margin-bottom: 1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #3498db 0%, #2c3e50 100%);
        padding: 1rem;
        border-radius: 8px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    .threat-card {
        border-left: 4px solid #3498db;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 6px;
        background: #f8f9fa;
        border: 1px solid #dee2e6;
    }
    .critical { border-left-color: #dc3545; }
    .high { border-left-color: #fd7e14; }
    .medium { border-left-color: #17a2b8; }
    .low { border-left-color: #28a745; }
</style>
""", unsafe_allow_html=True)

# Sample fallback data for fast loading
FALLBACK_THREATS = [
    {
        "id": "sample_1",
        "title": "New APT Group Targeting Financial Institutions",
        "source": "Threat Intelligence Feed",
        "category": "APT",
        "severity": "Critical",
        "published_date": "2025-07-25T10:00:00Z",
        "link": "https://example.com/threat1",
        "summary": "Advanced persistent threat group using sophisticated malware to target banking infrastructure. Multiple IOCs identified including C2 domains and file hashes.",
        "iocs": {
            "domains": ["malicious-c2.com", "bad-actor.net"],
            "ips": ["192.168.1.100", "10.0.0.50"],
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e", "5d41402abc4b2a76b9719d911017c592"]
        }
    },
    {
        "id": "sample_2", 
        "title": "Ransomware Campaign Using CVE-2024-12345",
        "source": "Security Research",
        "category": "Ransomware",
        "severity": "High",
        "published_date": "2025-07-24T15:30:00Z",
        "link": "https://example.com/threat2",
        "summary": "Active ransomware campaign exploiting recent vulnerability in web applications. Immediate patching recommended.",
        "iocs": {
            "cves": ["CVE-2024-12345"],
            "domains": ["ransom-payment.onion"],
            "hashes": ["a1b2c3d4e5f6789012345678901234567890abcd"]
        }
    },
    {
        "id": "sample_3",
        "title": "Phishing Campaign Impersonating Major Cloud Provider",
        "source": "Email Security",
        "category": "Phishing",
        "severity": "Medium",
        "published_date": "2025-07-23T09:15:00Z",
        "link": "https://example.com/threat3",
        "summary": "Large-scale phishing campaign using fake cloud service login pages to steal credentials.",
        "iocs": {
            "domains": ["fake-cloud-service.com", "phish-login.net"],
            "urls": ["https://fake-cloud-service.com/login", "https://phish-login.net/secure"]
        }
    }
]

class FastThreatIntelligence:
    """Optimized threat intelligence class with fast loading and fallback data."""
    
    def __init__(self):
        self.db_path = "threat_intel.db"
        self.fallback_data = FALLBACK_THREATS
        self._cached_threats = None
        self._last_cache_time = None
        
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics with fallback."""
        try:
            if os.path.exists(self.db_path):
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Quick stats query
                cursor.execute("SELECT COUNT(*) FROM threat_intel")
                total_threats = cursor.fetchone()[0]
                
                # Recent threats (last 7 days)
                week_ago = (datetime.now() - timedelta(days=7)).isoformat()
                cursor.execute("SELECT COUNT(*) FROM threat_intel WHERE created_at > ?", (week_ago,))
                recent_threats = cursor.fetchone()[0]
                
                conn.close()
                
                return {
                    "total_threats": total_threats,
                    "recent_threats": recent_threats,
                    "sources": 5,  # Approximate
                    "status": "connected"
                }
        except Exception as e:
            logger.warning(f"Database access failed: {e}")
            
        # Fallback stats
        return {
            "total_threats": len(self.fallback_data),
            "recent_threats": len(self.fallback_data),
            "sources": 3,
            "status": "fallback"
        }
    
    def get_threats(self, limit: int = 20, use_cache: bool = True) -> List[Dict]:
        """Get threats with caching and fallback."""
        
        # Use cache if available and recent
        if (use_cache and self._cached_threats and self._last_cache_time and 
            (time.time() - self._last_cache_time) < 300):  # 5 minute cache
            return self._cached_threats[:limit]
        
        threats = []
        
        try:
            if os.path.exists(self.db_path):
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, title, source, category, severity, published_date, 
                           link, summary, iocs, created_at
                    FROM threat_intel 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (limit * 2,))  # Get more to filter
                
                rows = cursor.fetchall()
                conn.close()
                
                for row in rows:
                    try:
                        iocs = json.loads(row[8]) if row[8] else {}
                        threats.append({
                            "id": row[0],
                            "title": row[1],
                            "source": row[2], 
                            "category": row[3] or "Unknown",
                            "severity": row[4] or "Medium",
                            "published_date": row[5],
                            "link": row[6],
                            "summary": row[7] or "No summary available",
                            "iocs": iocs,
                            "created_at": row[9]
                        })
                    except Exception as e:
                        logger.warning(f"Error parsing threat row: {e}")
                        continue
                        
                if threats:
                    self._cached_threats = threats
                    self._last_cache_time = time.time()
                    return threats[:limit]
                    
        except Exception as e:
            logger.warning(f"Database query failed: {e}")
        
        # Fallback to sample data
        logger.info("Using fallback threat data")
        return self.fallback_data[:limit]
    
    def search_iocs(self, query: str, limit: int = 10) -> List[Dict]:
        """Search IOCs with fallback."""
        if not query:
            return []
            
        query_lower = query.lower()
        results = []
        
        # Search in current threats
        threats = self.get_threats(limit=100)
        
        for threat in threats:
            matched = False
            
            # Search in IOCs
            for ioc_type, iocs in threat.get("iocs", {}).items():
                if isinstance(iocs, list):
                    for ioc in iocs:
                        if query_lower in str(ioc).lower():
                            threat["matched_ioc"] = ioc
                            threat["matched_type"] = ioc_type
                            results.append(threat)
                            matched = True
                            break
                    if matched:
                        break
            
            # Search in title/summary
            if not matched:
                if (query_lower in threat["title"].lower() or 
                    query_lower in threat["summary"].lower()):
                    threat["matched_type"] = "content"
                    results.append(threat)
            
            if len(results) >= limit:
                break
                
        return results

def render_header():
    """Render application header."""
    st.markdown('<h1 class="main-header">🛡️ TIFA - Elite Threat Intelligence</h1>', 
                unsafe_allow_html=True)
    st.markdown("*Fast-loading AI-powered threat intelligence platform*")

def render_metrics(intel: FastThreatIntelligence):
    """Render key metrics quickly."""
    stats = intel.get_database_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{stats['total_threats']}</h3>
            <p>Total Threats</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{stats['recent_threats']}</h3>
            <p>Recent (7d)</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{stats['sources']}</h3>
            <p>Active Sources</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        status_color = "🟢" if stats['status'] == "connected" else "🟡"
        st.markdown(f"""
        <div class="metric-card">
            <h3>{status_color}</h3>
            <p>System Status</p>
        </div>
        """, unsafe_allow_html=True)

def render_threat_card(threat: Dict, key_suffix: str = ""):
    """Render individual threat card."""
    severity = threat.get("severity", "Medium").lower()
    
    st.markdown(f"""
    <div class="threat-card {severity}">
        <h4>🎯 {threat['title']}</h4>
        <p><strong>📡 Source:</strong> {threat['source']} | 
           <strong>📂 Category:</strong> {threat.get('category', 'Unknown')} | 
           <strong>🔥 Severity:</strong> {threat.get('severity', 'Medium')}</p>
        <p>{threat['summary'][:200]}...</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Show IOCs in expander
    if threat.get("iocs"):
        with st.expander(f"🔍 IOCs - {threat['title'][:30]}...", key=f"iocs_{threat['id']}_{key_suffix}"):
            ioc_data = []
            for ioc_type, iocs in threat["iocs"].items():
                if isinstance(iocs, list):
                    for ioc in iocs:
                        ioc_data.append({"Type": ioc_type.title(), "IOC": str(ioc)})
            
            if ioc_data:
                df = pd.DataFrame(ioc_data)
                st.dataframe(df, use_container_width=True, hide_index=True)

def render_dashboard_tab(intel: FastThreatIntelligence):
    """Render main dashboard."""
    st.subheader("📊 **Threat Intelligence Dashboard**")
    
    # Get threats
    threats = intel.get_threats(limit=10)
    
    if threats:
        # Quick visualization
        col1, col2 = st.columns(2)
        
        with col1:
            # Severity distribution
            severity_counts = {}
            for threat in threats:
                sev = threat.get("severity", "Medium")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            if severity_counts:
                fig = px.pie(
                    values=list(severity_counts.values()),
                    names=list(severity_counts.keys()),
                    title="Threat Severity Distribution",
                    color_discrete_map={
                        'Critical': '#dc3545',
                        'High': '#fd7e14', 
                        'Medium': '#17a2b8',
                        'Low': '#28a745'
                    }
                )
                st.plotly_chart(fig, use_container_width=True, key="severity_pie")
        
        with col2:
            # Category distribution  
            category_counts = {}
            for threat in threats:
                cat = threat.get("category", "Unknown")
                category_counts[cat] = category_counts.get(cat, 0) + 1
            
            if category_counts:
                fig = px.bar(
                    x=list(category_counts.keys()),
                    y=list(category_counts.values()),
                    title="Threats by Category",
                    color=list(category_counts.values()),
                    color_continuous_scale="viridis"
                )
                st.plotly_chart(fig, use_container_width=True, key="category_bar")
        
        # Recent threats
        st.subheader("🚨 **Recent Threats**")
        for i, threat in enumerate(threats[:5]):
            render_threat_card(threat, f"dashboard_{i}")
    else:
        st.warning("No threat data available. Check connection or wait for data to load.")

def render_ioc_search_tab(intel: FastThreatIntelligence):
    """Render IOC search functionality."""
    st.subheader("🔍 **IOC Hunter**")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        search_query = st.text_input(
            "Search IOCs, domains, IPs, hashes, CVEs:",
            placeholder="e.g., malicious.com, 192.168.1.1, d41d8cd98f00b204e9800998ecf8427e",
            help="Enter any IOC to search across threat intelligence"
        )
    
    with col2:
        search_button = st.button("🔍 **Search**", type="primary", use_container_width=True)
    
    if search_query or search_button:
        if search_query:
            with st.spinner("🕵️ Hunting for IOC matches..."):
                results = intel.search_iocs(search_query, limit=20)
            
            if results:
                st.success(f"🎯 Found **{len(results)}** threats containing: `{search_query}`")
                
                # Results summary
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Matches Found", len(results))
                
                with col2:
                    sources = len(set(r["source"] for r in results))
                    st.metric("Sources", sources)
                
                with col3:
                    critical = len([r for r in results if r.get("severity") == "Critical"])
                    st.metric("Critical", critical)
                
                # Show results
                st.markdown("### 🎯 **Hunt Results**")
                for i, result in enumerate(results[:10]):
                    if result.get("matched_ioc"):
                        st.info(f"**Match:** {result['matched_ioc']} ({result.get('matched_type', 'unknown')})")
                    render_threat_card(result, f"search_{i}")
            else:
                st.warning(f"🔍 No threats found containing: **{search_query}**")
                st.info("💡 Try different search terms or check if the IOC exists in our database")
        else:
            st.info("💡 Enter an IOC above to start hunting")

def render_analytics_tab(intel: FastThreatIntelligence):
    """Render analytics and trends."""
    st.subheader("📈 **Analytics & Trends**")
    
    threats = intel.get_threats(limit=50)
    
    if threats:
        # Convert to DataFrame for analysis
        df_data = []
        for threat in threats:
            df_data.append({
                'date': threat.get('published_date', '2025-07-25T00:00:00Z')[:10],
                'category': threat.get('category', 'Unknown'),
                'severity': threat.get('severity', 'Medium'),
                'source': threat.get('source', 'Unknown'),
                'ioc_count': len([ioc for iocs in threat.get('iocs', {}).values() for ioc in (iocs if isinstance(iocs, list) else [iocs])])
            })
        
        df = pd.DataFrame(df_data)
        df['date'] = pd.to_datetime(df['date'])
        
        # Timeline analysis
        daily_counts = df.groupby(df['date'].dt.date).size()
        
        fig = px.line(
            x=daily_counts.index,
            y=daily_counts.values,
            title="Daily Threat Intelligence Volume",
            labels={'x': 'Date', 'y': 'Number of Threats'}
        )
        st.plotly_chart(fig, use_container_width=True, key="timeline_chart")
        
        # Top sources
        st.subheader("📡 **Top Threat Sources**")
        source_counts = df['source'].value_counts().head(5)
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.bar(
                x=source_counts.values,
                y=source_counts.index,
                orientation='h',
                title="Most Active Sources"
            )
            st.plotly_chart(fig, use_container_width=True, key="sources_bar")
        
        with col2:
            # IOC statistics
            st.markdown("**🎯 IOC Statistics:**")
            total_iocs = df['ioc_count'].sum()
            avg_iocs = df['ioc_count'].mean()
            max_iocs = df['ioc_count'].max()
            
            st.metric("Total IOCs", int(total_iocs))
            st.metric("Avg IOCs/Threat", f"{avg_iocs:.1f}")
            st.metric("Max IOCs/Threat", int(max_iocs))
    else:
        st.info("Insufficient data for analytics. Check back after more threats are collected.")

def main():
    """Main application entry point."""
    render_header()
    
    # Initialize intelligence system
    intel = FastThreatIntelligence()
    
    # Render metrics
    render_metrics(intel)
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["📊 **Dashboard**", "🔍 **IOC Hunter**", "📈 **Analytics**"])
    
    with tab1:
        render_dashboard_tab(intel)
    
    with tab2:
        render_ioc_search_tab(intel)
    
    with tab3:
        render_analytics_tab(intel)
    
    # Footer
    st.markdown("---")
    st.markdown("🛡️ **TIFA** - Elite Threat Intelligence Feed Aggregator | Optimized for Performance")

if __name__ == "__main__":
    main()
