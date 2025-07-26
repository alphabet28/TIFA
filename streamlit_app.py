"""
🛡️ TIFA - Elite Threat Intelligence Feed Aggregator
Streamlit Cloud Entry Point
"""

# Import required packages
import streamlit as st
import os
import sys

# Ensure the app can find all modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure Streamlit page
st.set_page_config(
    page_title="🛡️ TIFA - Elite Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/Deepam02/TIFA',
        'Report a bug': "https://github.com/Deepam02/TIFA/issues",
        'About': "# 🛡️ TIFA - Elite Threat Intelligence Feed Aggregator\nAI-powered threat intelligence aggregation and analysis platform"
    }
)

# Load secrets for Streamlit Cloud
if hasattr(st, 'secrets'):
    # Set environment variables from Streamlit secrets
    if 'GEMINI_API_KEY_1' in st.secrets:
        os.environ['GEMINI_API_KEY_1'] = st.secrets["GEMINI_API_KEY_1"]
    if 'GEMINI_API_KEY_2' in st.secrets:
        os.environ['GEMINI_API_KEY_2'] = st.secrets["GEMINI_API_KEY_2"]

# Import and run the main application
try:
    # Import main function from app.py
    from app import main
    
    # Run the application
    if __name__ == "__main__":
        main()
        
except Exception as e:
    st.error(f"🚨 Application Error: {str(e)}")
    st.info("Please check the configuration and try refreshing the page.")
    
    # Show debug information in development
    if st.checkbox("Show Debug Information"):
        st.code(f"Error details: {str(e)}")
        import traceback
        st.code(traceback.format_exc())
