"""
Main application file for the Threat Intelligence Dashboard.
This script initializes all components and launches the Streamlit UI.
"""
import streamlit as st
import pandas as pd
import logging

from config import Config
from models import ThreatIntelItem
from database import ThreatIntelDatabase
from core import AIAnalyzer, IOCExtractor, FeedCollector

# --- Setup & Initialization ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

st.set_page_config(page_title=Config.APP_TITLE, page_icon=Config.APP_ICON, layout="wide")

# --- Aggregator Class ---
class ThreatIntelAggregator:
    """Orchestrates the collection and processing of threat intelligence."""
    def __init__(self):
        self.db = ThreatIntelDatabase()
        self.ioc_extractor = IOCExtractor()
        self.feed_collector = FeedCollector(self.db, self.ioc_extractor)
        self.ai_analyzer = AIAnalyzer()

    def run_aggregation(self):
        """Runs the full aggregation process for all configured feeds."""
        logger.info("Starting threat intelligence aggregation...")
        with st.spinner("🔄 Collecting and analyzing threat feeds..."):
            for feed_info in Config.THREAT_FEEDS:
                new_items = self.feed_collector.fetch_feed(feed_info)
                for item in new_items:
                    analysis = self.ai_analyzer.analyze(f"{item.title}\n{item.summary}")
                    item.summary = analysis.get("summary", item.summary)
                    item.severity = analysis.get("severity", "Medium")
                    self.db.save_item(item)
        logger.info("Threat intelligence aggregation finished.")
        st.success("✅ Feeds refreshed successfully!")

# --- UI Components ---
def display_threat_item(item: ThreatIntelItem):
    """Renders a single threat item in a consistent format."""
    severity_color = {"Critical": "red", "High": "orange", "Medium": "blue", "Low": "green"}.get(item.severity, "grey")
    
    with st.container():
        st.markdown(f"""
        <div style="border-left: 5px solid {severity_color}; padding: 10px; border-radius: 5px; margin-bottom: 10px; background-color: #f0f2f6;">
            <h4>{item.title}</h4>
            <p><strong>Source:</strong> {item.source} | <strong>Published:</strong> {item.published_date.split('T')[0]}</p>
            <p>{item.summary}</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander("View Details & IOCs"):
            st.markdown(f"[Read full article]({item.link})", unsafe_allow_html=True)
            st.json({k: list(v) for k, v in item.iocs.items() if v})

def main_dashboard(aggregator: ThreatIntelAggregator):
    """The main dashboard view showing recent threats."""
    st.title("🔴 Live Threat Feed")
    
    if st.button("🔄 Refresh Feeds"):
        aggregator.run_aggregation()
        st.rerun()

    threats = aggregator.db.get_recent_threats()
    if not threats:
        st.info("No threat intelligence data found. Click 'Refresh Feeds' to start.")
        return

    for item in threats:
        display_threat_item(item)

def ioc_search(aggregator: ThreatIntelAggregator):
    """The IOC search page."""
    st.title("🔍 IOC Search")
    query = st.text_input("Search for IP, Domain, Hash, or CVE:", placeholder="e.g., 1.1.1.1 or CVE-2021-44228")

    if query:
        results = aggregator.db.search_ioc(query)
        st.write(f"Found **{len(results)}** results for `{query}`.")
        for item in results:
            display_threat_item(item)

def analytics_dashboard(aggregator: ThreatIntelAggregator):
    """The analytics and statistics page."""
    st.title("📊 Analytics Dashboard")
    stats = aggregator.db.get_statistics()

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Threats", stats.get("total_threats", 0))
    col2.metric("Total IOCs", stats.get("total_iocs", 0))
    col3.metric("Total Sources", stats.get("total_sources", 0))
    
    st.info(f"Last update: {stats.get('last_update', 'N/A')}")

    # Prepare data for charts
    threats = aggregator.db.get_recent_threats(limit=200)
    if threats:
        df = pd.DataFrame([t.to_dict() for t in threats])
        
        st.subheader("Threats by Source")
        source_counts = df['source'].value_counts()
        st.bar_chart(source_counts)

        st.subheader("Threats by Severity")
        severity_counts = df['severity'].value_counts()
        st.bar_chart(severity_counts)

# --- Main Application ---
def main():
    """Main function to run the Streamlit application."""
    st.sidebar.title(Config.APP_TITLE)
    
    # Initialize the aggregator
    if 'aggregator' not in st.session_state:
        st.session_state.aggregator = ThreatIntelAggregator()
    
    aggregator = st.session_state.aggregator

    page = st.sidebar.radio("Navigation", ["Dashboard", "IOC Search", "Analytics"])

    if page == "Dashboard":
        main_dashboard(aggregator)
    elif page == "IOC Search":
        ioc_search(aggregator)
    elif page == "Analytics":
        analytics_dashboard(aggregator)

if __name__ == "__main__":
    main()
