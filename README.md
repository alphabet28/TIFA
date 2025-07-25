# 🛡️ Threat Intelligence Feed Aggregator

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Gradio](https://img.shields.io/badge/gradio-4.0+-orange.svg)](https://gradio.app/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AI Powered](https://img.shields.io/badge/AI-Gemini%202.5-green.svg)](https://ai.google.dev/)

> An AI-powered threat intelligence aggregation platform that consolidates and analyzes cyber threat data from multiple online sources using Google Gemini AI.

![Dashboard Preview](https://via.placeholder.com/800x400/1e293b/ffffff?text=Threat+Intelligence+Dashboard)

## 🌟 Features

### 🤖 **AI-Powered Analysis**
- **Google Gemini Integration**: Uses Gemini 2.5 Flash for intelligent threat analysis
- **Smart API Key Rotation**: Automatically switches between multiple API keys
- **Model Fallback System**: 4-tier model hierarchy for maximum reliability
- **Beautiful Summaries**: Structured threat analysis with actionable insights

### 🔍 **Multi-Source Intelligence**
- **5 Premium Sources**: CISA, SANS, Krebs on Security, Malwarebytes, ThreatPost
- **RSS/Atom Parsing**: Real-time feed aggregation
- **Auto-refresh**: Configurable update intervals
- **Source Verification**: Validated threat intelligence feeds

### 📊 **IOC Extraction**
- **9 IOC Types**: IPs, domains, URLs, hashes (MD5/SHA1/SHA256), CVEs, emails
- **Regex Patterns**: Advanced pattern matching for indicators
- **Auto-filtering**: Excludes common false positives
- **Contextual Analysis**: IOCs linked to threat context

### 🎯 **Professional Dashboard**
- **Clean UI**: Modern Gradio interface with professional styling
- **Severity Filtering**: Filter threats by Critical/High/Medium/Low
- **Advanced Search**: Full-text search across all threats
- **Real-time Stats**: Live threat statistics and AI usage metrics

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- Google Gemini API keys ([Get them here](https://makersuite.google.com/app/apikey))

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure API Keys**

Edit `config.py` and add your Gemini API keys:
```python
GEMINI_API_KEYS = [
    "your-first-api-key-here",
    "your-second-api-key-here"
]
```

4. **Run the application**

**For local development:**
```bash
python main.py
```

**For production/deployment:**
```bash
python app.py
```

5. **Open your browser**
Navigate to `http://localhost:7860`

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   RSS/Atom     │───▶│   Feed Parser    │───▶│   Database      │
│   Sources       │    │   (feedparser)   │    │   (SQLite)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   IOC Extract   │◀───│   Aggregator     │───▶│   AI Analyzer   │
│   (Regex)       │    │   (Main Logic)   │    │   (Gemini)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Dashboard      │
                       │   (Gradio UI)    │
                       └──────────────────┘
```

## 📁 Project Structure

```
threat-intelligence-aggregator/
├── 📄 app.py                 # Production entry point
├── 📄 main.py                # Development entry point
├── 📄 config.py              # Configuration settings
├── 📄 models.py              # Data models
├── 📄 database.py            # Database operations
├── 📄 feed_collector.py      # RSS/Atom feed processing
├── 📄 ioc_extractor.py       # IOC pattern matching
├── 📄 ai_analyzer.py         # AI analysis coordinator
├── 📄 gemini_analyzer.py     # Gemini AI implementation
├── 📄 aggregator.py          # Main business logic
├── 📄 dashboard.py           # Gradio UI interface
├── 📄 requirements.txt       # Python dependencies
├── 📄 .gitignore            # Git ignore rules
├── 📄 README.md             # This file
├── 📄 DEPLOYMENT.md         # Deployment guide
└── 📄 RUN_GUIDE.md          # Quick run guide
```

## 🤖 AI Integration

### Gemini Model Hierarchy
1. **Gemini 2.5 Flash** - Primary (10 RPM, 250K TPM, 250 RPD)
2. **Gemini 2.5 Flash-Lite** - Secondary (15 RPM, 250K TPM, 1000 RPD)
3. **Gemini 2.0 Flash** - Backup (15 RPM, 1M TPM, 200 RPD)
4. **Gemini 2.0 Flash-Lite** - Fallback (30 RPM, 1M TPM, 200 RPD)

### AI Analysis Output Example
```
🎯 THREAT CLASSIFICATION
Type: Ransomware
Severity: High
Confidence: High

🔍 KEY FINDINGS
• Active ransomware campaign targeting healthcare sector
• New variant of LockBit using advanced evasion techniques
• 127 indicators of compromise identified

⚠️ IMPACT ASSESSMENT
• Affected Systems: Windows networks, domain controllers
• Attack Vector: Phishing emails with malicious attachments
• Potential Damage: Data encryption, system lockout, ransom demands

🛡️ DEFENSIVE ACTIONS
• Immediate: Block identified IOCs in security tools
• Short-term: Update endpoint protection signatures
• Monitoring: Watch for behavioral indicators in network traffic

📊 IOC SUMMARY
• 127 indicators extracted from content
• Primary types: File Hashes, IP Addresses, Domains
```

## 🔧 Configuration

### Environment Variables (Recommended)
```bash
export GEMINI_API_KEY_1="your-first-key"
export GEMINI_API_KEY_2="your-second-key"
export AI_PROVIDER="gemini"
export SERVER_PORT="7860"
```

### Threat Sources Configuration
```python
THREAT_FEEDS = [
    {
        'name': 'US-CERT CISA',
        'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
        'type': 'rss'
    },
    # ... more sources
]
```

## 🌐 Deployment

### Hugging Face Spaces (Recommended)
1. Fork this repository
2. Create a new Space on Hugging Face
3. Connect your repository
4. Set environment variables for API keys
5. Deploy automatically

### Docker
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 7860
CMD ["python", "app.py"]
```

### Local Development
```bash
python main.py  # Auto-opens browser, localhost only
```

## 📊 Performance

### Capacity with 2 API Keys
- **Total RPM**: 120+ requests per minute
- **Daily Capacity**: 3,500+ requests per day
- **Concurrent Users**: 10+ simultaneous users
- **Response Time**: <2 seconds average

### System Limits
- **Max Feeds**: 20 items per source
- **Auto-refresh**: Every 5 minutes
- **Search Results**: 50 per query
- **Export Limit**: 100 items

## 🛠️ Development

### Adding New Threat Sources
1. Edit `config.py` THREAT_FEEDS
2. Add RSS/Atom feed URL
3. Test with feed validator

### Extending IOC Patterns
1. Update `config.py` IOC_PATTERNS
2. Add regex patterns for new indicator types
3. Test pattern matching

### Customizing AI Prompts
1. Edit `gemini_analyzer.py`
2. Modify prompt templates
3. Test with various threat types

## 🔍 Troubleshooting

### Common Issues

**"AI Analysis unavailable"**
- Check API keys are valid and not expired
- Verify internet connection
- Monitor rate limits in logs

**"No threats found"**
- RSS feeds may be temporarily down
- Check feed URLs are accessible
- Try manual refresh

**Performance Issues**
- Check database size (SQLite has limits)
- Monitor memory usage
- Consider database cleanup

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Google Gemini AI** for powerful threat analysis capabilities
- **Gradio** for the amazing web interface framework
- **CISA, SANS, Krebs Security** for reliable threat intelligence feeds
- **Young Graduates Hiring Program** for the hackathon opportunity

## 📞 Support

- **Documentation**: Check `DEPLOYMENT.md` and `RUN_GUIDE.md`
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions

---

**🎯 Built for the Young Graduates Hiring Program Hackathon Challenge**

*A comprehensive cybersecurity threat intelligence platform designed to help security teams proactively monitor and respond to emerging threats.*
