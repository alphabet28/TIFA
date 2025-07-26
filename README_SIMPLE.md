# 🛡️ Threat Intelligence Feed Aggregator

A simple, effective threat intelligence platform for SOC teams and security researchers.

## 🎯 Core Features

- **📡 Real-time Feed Monitoring** - Automatically collects from RSS feeds, security blogs
- **🤖 AI-Powered Summarization** - Uses Google Gemini for intelligent threat analysis  
- **🔍 IOC Extraction & Search** - Automatically extracts and indexes indicators of compromise
- **📊 Clean Dashboard** - Simple, responsive Gradio interface for monitoring and analysis
- **⚡ Fast Deployment** - Modular design for quick setup and deployment

## 🚀 Quick Start

### 1. Installation
```bash
git clone https://github.com/Deepam02/TIFA.git
cd threat-intelligence-feed--aggregator
pip install -r requirements.txt
```

### 2. Configuration
```bash
# Copy and edit configuration
cp .env.example .env
# Add your Google Gemini API key (optional)
```

### 3. Run Demo
```bash
python demo_comprehensive.py
```

### 4. Launch Dashboard
```bash
python main_simple.py
```

Access at: http://127.0.0.1:7861

## 📱 Dashboard Features

### 🔴 Live Feed Tab
- Real-time threat intelligence display
- One-click feed refresh
- Severity-based color coding
- Clean, readable threat summaries

### 📊 Analytics Tab  
- Threat statistics and metrics
- Source analysis
- IOC counts and breakdowns
- Last update tracking

### 🔍 IOC Search Tab
- Search by IP, domain, hash, URL
- Instant results from threat database
- Match highlighting and context
- Export-ready format

## 🛠️ Architecture

```
├── aggregator.py      # Main orchestration logic
├── feed_collector.py  # RSS/feed collection
├── ioc_extractor.py   # IOC parsing and extraction  
├── ai_analyzer.py     # Gemini AI integration
├── database.py        # SQLite storage and search
├── simple_dashboard.py # Clean Gradio interface
└── config.py          # Configuration management
```

## 📡 Supported Feeds

- **Cybersecurity Blogs** - Krebs, Schneier, etc.
- **Threat Intelligence** - SANS, FireEye, CrowdStrike
- **Vulnerability Feeds** - NVD, CVE databases
- **Custom RSS/Atom** - Add your own sources

## 🎯 Use Cases

### SOC Teams
- Centralized threat monitoring dashboard
- Quick IOC lookup and verification
- Automated feed aggregation
- Severity-based alert prioritization

### Security Researchers  
- Comprehensive threat intelligence collection
- Historical threat analysis
- IOC correlation and tracking
- Export capabilities for further analysis

### Incident Response
- Fast threat context gathering
- IOC validation against known threats
- Timeline reconstruction
- Evidence collection support

## 🔧 Configuration

### Feed Sources
Edit `config.py` to add custom feeds:
```python
THREAT_FEEDS = [
    {
        "name": "Custom Feed",
        "url": "https://example.com/feed.xml",
        "category": "threat_intel"
    }
]
```

### AI Integration
Add Gemini API key to `.env`:
```
GOOGLE_API_KEY=your_api_key_here
```

### Database
SQLite database automatically created at:
- `threat_intel.db` - Main database
- Automatic schema creation
- Built-in backup support

## 📊 API Endpoints

The dashboard exposes these core functions:
- `refresh_feeds()` - Update threat intelligence
- `search_iocs(query)` - Search for indicators
- `get_statistics()` - Database metrics
- `get_threat_summary()` - Recent threats

## 🚀 Deployment

### Local Development
```bash
python main_simple.py
```

### Production Deployment
```bash
# With public access
python main_simple.py --share
```

### Docker (Optional)
```dockerfile
FROM python:3.9-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "main_simple.py"]
```

## 📈 Performance

- **Collection Speed**: ~100 feeds/minute
- **Database**: SQLite with indexing
- **Memory Usage**: <100MB typical
- **Response Time**: <1s for searches
- **Concurrent Users**: 10+ supported

## 🔒 Security

- Input sanitization for IOC searches
- SQL injection protection
- Rate limiting on API calls
- Secure API key handling
- Local database storage

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality  
4. Submit pull request

## 📄 License

MIT License - see LICENSE file

## 🆘 Support

- 📧 Issues: GitHub Issues page
- 📖 Documentation: README and code comments
- 🔧 Configuration: Check config.py
- 🐛 Debugging: Enable logging in main.py

---

**Built for simplicity, designed for effectiveness** 🛡️
