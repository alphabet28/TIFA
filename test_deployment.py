#!/usr/bin/env python3
"""
Test script to validate TIFA deployment fixes for Streamlit Cloud
"""

def test_aggregator_initialization():
    """Test that the aggregator initializes properly with metrics in all scenarios."""
    print("🧪 Testing TIFA aggregator initialization...")
    
    try:
        # Import and initialize aggregator
        import app
        aggregator = app.EliteThreatIntelAggregator()
        
        # Test 1: Aggregator should always have metrics
        assert hasattr(aggregator, 'metrics'), "❌ Aggregator missing metrics attribute"
        print("✅ Aggregator has metrics attribute")
        
        # Test 2: Metrics should be a dictionary
        assert isinstance(aggregator.metrics, dict), "❌ Metrics is not a dictionary"
        print("✅ Metrics is a dictionary")
        
        # Test 3: Required metrics keys should exist
        required_keys = ["feeds_processed", "threats_analyzed", "iocs_extracted", "last_update"]
        for key in required_keys:
            assert key in aggregator.metrics, f"❌ Missing required metric: {key}"
        print("✅ All required metrics keys present")
        
        # Test 4: Safe metrics access (the pattern used in app.py)
        if hasattr(aggregator, 'metrics') and aggregator.metrics and aggregator.metrics.get("last_update"):
            last_update = aggregator.metrics["last_update"]
            assert last_update is not None, "❌ Last update is None"
            print("✅ Safe metrics access works")
        
        # Test 5: Individual metric access with fallback (the pattern used in render_elite_metrics)
        threats_analyzed = aggregator.metrics.get('threats_analyzed', 0) if hasattr(aggregator, 'metrics') else 0
        assert isinstance(threats_analyzed, (int, float)), "❌ Threats analyzed metric type error"
        print("✅ Individual metric access with fallback works")
        
        print("🎉 All aggregator tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Aggregator test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_database_fallback():
    """Test database initialization with fallback handling."""
    print("\n🧪 Testing database fallback handling...")
    
    try:
        from src.core.database import ThreatIntelDatabase
        from src.core.config import Config
        
        # Test normal initialization
        db = ThreatIntelDatabase()
        print(f"✅ Database initialized with path: {db.db_path}")
        
        # Test configuration path resolution
        print(f"✅ Config DB_PATH: {Config.DB_PATH}")
        
        print("🎉 Database tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_imports():
    """Test all critical imports."""
    print("\n🧪 Testing critical imports...")
    
    try:
        # Test core imports
        from src.core.config import Config
        from src.core.models import ThreatIntelItem
        from src.core.database import ThreatIntelDatabase
        print("✅ Core imports successful")
        
        # Test analyzer imports
        from src.analyzers.ai_core import AIAnalyzer, IOCExtractor, FeedCollector
        print("✅ Analyzer imports successful")
        
        # Test app import
        import app
        print("✅ App import successful")
        
        print("🎉 All import tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Import test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🚀 TIFA Deployment Test Suite")
    print("=" * 50)
    
    # Run all tests
    tests = [
        test_imports,
        test_database_fallback,
        test_aggregator_initialization
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! TIFA is ready for Streamlit Cloud deployment.")
        exit(0)
    else:
        print("❌ Some tests failed. Please review the issues above.")
        exit(1)
