# 🚀 **How to Run the Threat Intelligence Aggregator**

## **Option 1: Using app.py (Recommended for Production/HF Spaces)**

```bash
cd "c:\Users\Dell\Desktop\ionasim\threat-intelligence-feed--aggregator"
python app.py
```

**Features:**
- ✅ Optimized for Hugging Face Spaces deployment
- ✅ Error handling and fallback interface
- ✅ Production logging configuration
- ✅ Runs on `http://0.0.0.0:7860` (accessible from any IP)
- ✅ Queue management for concurrent users

## **Option 2: Using main.py (Local Development)**

```bash
cd "c:\Users\Dell\Desktop\ionasim\threat-intelligence-feed--aggregator"
python main.py
```

**Features:**
- ✅ Local development focused
- ✅ Auto-opens browser
- ✅ Runs on `http://127.0.0.1:7860` (localhost only)
- ✅ Share=True for public tunneling

## **Current Status** ✅

Your app is **currently running** with:
- **URL**: http://0.0.0.0:7860
- **AI**: Gemini 2.5 Flash (corrected models)
- **Status**: Ready for testing!

## **Fixed Gemini Models** ✅

Updated to use the correct model priority:

1. **Gemini 2.5 Flash** (10 RPM, 250K TPM, 250 RPD) - **Best**
2. **Gemini 2.5 Flash-Lite** (15 RPM, 250K TPM, 1000 RPD) - **Good**  
3. **Gemini 2.0 Flash** (15 RPM, 1M TPM, 200 RPD) - **Backup**
4. **Gemini 2.0 Flash-Lite** (30 RPM, 1M TPM, 200 RPD) - **Fallback**

## **Quick Test** 🧪

1. Open your browser to: **http://localhost:7860**
2. Click **"🔄 Refresh Feeds"** to load threats
3. Watch the AI generate beautiful summaries!
4. Try the severity filter dropdown

## **For Deployment** 🌐

Use `app.py` when deploying to:
- Hugging Face Spaces
- Docker containers  
- Cloud platforms
- Production servers

Use `main.py` for:
- Local development
- Testing new features
- Debug sessions
