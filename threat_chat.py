"""
Advanced AI Chat Assistant for Threat Intelligence
Provides intelligent threat analysis, recommendations, and interactive guidance
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import re
from ai_analyzer import AIAnalyzer

logger = logging.getLogger(__name__)

class ThreatIntelligenceChat:
    """Advanced AI-powered chat assistant for threat intelligence"""
    
    def __init__(self, ai_analyzer: AIAnalyzer):
        self.ai_analyzer = ai_analyzer
        self.logger = logging.getLogger(__name__)
        self.conversation_history = []
        
        # Predefined expert responses for common queries
        self.expert_responses = {
            'apt': """
            🎯 **Advanced Persistent Threat (APT) Analysis**
            
            APTs are sophisticated, sustained attacks typically by nation-states or advanced criminal groups.
            
            **Key Characteristics:**
            • **Persistence**: Long-term presence in networks
            • **Stealth**: Advanced evasion techniques
            • **Targeted**: Specific organizations or data
            • **Multi-stage**: Complex attack chains
            
            **Detection Strategies:**
            • Behavioral analysis and anomaly detection
            • Network traffic analysis for C2 communications
            • Endpoint detection and response (EDR)
            • Threat hunting with IOCs and TTPs
            """,
            
            'ransomware': """
            🔒 **Ransomware Threat Analysis**
            
            Ransomware is malware that encrypts victim data and demands payment for decryption.
            
            **Current Trends:**
            • **Double Extortion**: Data theft + encryption
            • **RaaS Models**: Ransomware-as-a-Service
            • **Supply Chain**: Targeting MSPs and software vendors
            • **Critical Infrastructure**: Healthcare, energy, government
            
            **Mitigation Strategies:**
            • Regular offline backups and recovery testing
            • Network segmentation and access controls
            • Employee security awareness training
            • Patch management and vulnerability assessment
            """,
            
            'ioc': """
            🔍 **Indicators of Compromise (IOC) Intelligence**
            
            IOCs are forensic evidence of potential security incidents on networks or systems.
            
            **Types of IOCs:**
            • **Network**: IP addresses, domains, URLs
            • **File**: Hashes (MD5, SHA1, SHA256)
            • **Registry**: Windows registry modifications
            • **Process**: Unusual process behaviors
            
            **Best Practices:**
            • Contextualize IOCs with threat intelligence
            • Implement automated IOC feeds
            • Correlate across multiple data sources
            • Regular IOC aging and relevance assessment
            """,
            
            'mitre': """
            🛡️ **MITRE ATT&CK Framework**
            
            MITRE ATT&CK is a knowledge base of adversary tactics and techniques.
            
            **Key Components:**
            • **Tactics**: High-level adversary goals
            • **Techniques**: How tactics are achieved
            • **Procedures**: Specific implementations
            • **Mitigations**: Defensive countermeasures
            
            **Application Areas:**
            • Threat hunting and detection development
            • Security control assessment and gap analysis
            • Adversary emulation and red teaming
            • Incident response and forensic analysis
            """
        }
    
    async def process_chat_message(self, message: str, context: Optional[Dict] = None) -> str:
        """Process chat message and provide intelligent response"""
        try:
            message_lower = message.lower()
            
            # Add to conversation history
            self.conversation_history.append({
                'timestamp': datetime.now().isoformat(),
                'user_message': message,
                'context': context
            })
            
            # Check for predefined expert responses
            for keyword, response in self.expert_responses.items():
                if keyword in message_lower:
                    return self._format_chat_response(response, "Expert Knowledge")
            
            # Handle specific query types
            if any(word in message_lower for word in ['threat', 'attack', 'malware', 'vulnerability']):
                return await self._analyze_threat_query(message, context)
            elif any(word in message_lower for word in ['recommend', 'suggest', 'advice', 'help']):
                return await self._provide_recommendations(message, context)
            elif any(word in message_lower for word in ['explain', 'what is', 'how does']):
                return await self._explain_concept(message, context)
            else:
                return await self._general_ai_response(message, context)
                
        except Exception as e:
            logger.error(f"Error processing chat message: {e}")
            return self._format_chat_response(
                "I apologize, but I encountered an error processing your request. Please try rephrasing your question.",
                "Error"
            )
    
    async def _analyze_threat_query(self, message: str, context: Optional[Dict]) -> str:
        """Analyze threat-related queries"""
        try:
            prompt = f"""
            As a cybersecurity threat intelligence expert, analyze this query and provide detailed insights:
            
            Query: {message}
            
            Please provide:
            1. Threat analysis and assessment
            2. Potential impact and risk factors
            3. Recommended detection methods
            4. Mitigation strategies
            5. Related threat intelligence
            
            Format your response professionally for a security operations team.
            """
            
            response = await self.ai_analyzer.analyze_text_async(prompt)
            return self._format_chat_response(response, "Threat Analysis")
            
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}")
            return self._format_chat_response(
                "Unable to provide threat analysis at this time. Please check your AI configuration.",
                "Analysis Error"
            )
    
    async def _provide_recommendations(self, message: str, context: Optional[Dict]) -> str:
        """Provide security recommendations"""
        try:
            context_info = ""
            if context and 'recent_threats' in context:
                context_info = f"Recent threats in system: {len(context['recent_threats'])} threats detected"
            
            prompt = f"""
            As a cybersecurity consultant, provide actionable recommendations for this request:
            
            Request: {message}
            Context: {context_info}
            
            Please provide:
            1. Immediate actions to take
            2. Short-term security improvements
            3. Long-term strategic recommendations
            4. Risk assessment and prioritization
            5. Implementation guidance
            
            Focus on practical, implementable solutions.
            """
            
            response = await self.ai_analyzer.analyze_text_async(prompt)
            return self._format_chat_response(response, "Security Recommendations")
            
        except Exception as e:
            logger.error(f"Error providing recommendations: {e}")
            return self._format_chat_response(
                "Unable to provide recommendations at this time. Please try again later.",
                "Recommendation Error"
            )
    
    async def _explain_concept(self, message: str, context: Optional[Dict]) -> str:
        """Explain cybersecurity concepts"""
        try:
            prompt = f"""
            As a cybersecurity educator, explain this concept clearly and comprehensively:
            
            Question: {message}
            
            Please provide:
            1. Clear definition and explanation
            2. Real-world examples and use cases
            3. Current trends and developments
            4. Best practices and recommendations
            5. Related concepts and further reading
            
            Make it accessible but technically accurate for security professionals.
            """
            
            response = await self.ai_analyzer.analyze_text_async(prompt)
            return self._format_chat_response(response, "Concept Explanation")
            
        except Exception as e:
            logger.error(f"Error explaining concept: {e}")
            return self._format_chat_response(
                "Unable to explain the concept at this time. Please try rephrasing your question.",
                "Explanation Error"
            )
    
    async def _general_ai_response(self, message: str, context: Optional[Dict]) -> str:
        """Handle general queries with AI"""
        try:
            prompt = f"""
            As a cybersecurity threat intelligence assistant, respond to this query:
            
            Query: {message}
            
            Provide a helpful, accurate, and professional response focused on cybersecurity and threat intelligence.
            If the query is outside cybersecurity scope, politely redirect to security-related topics.
            """
            
            response = await self.ai_analyzer.analyze_text_async(prompt)
            return self._format_chat_response(response, "AI Assistant")
            
        except Exception as e:
            logger.error(f"Error in general AI response: {e}")
            return self._format_chat_response(
                "I'm having trouble processing your request. Please try asking about specific cybersecurity topics.",
                "General Error"
            )
    
    def _format_chat_response(self, content: str, response_type: str) -> str:
        """Format chat response with professional styling"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Determine icon based on response type
        icons = {
            "Expert Knowledge": "🎓",
            "Threat Analysis": "🔍", 
            "Security Recommendations": "💡",
            "Concept Explanation": "📚",
            "AI Assistant": "🤖",
            "Error": "⚠️",
            "Analysis Error": "❌",
            "Recommendation Error": "❌",
            "Explanation Error": "❌",
            "General Error": "❌"
        }
        
        icon = icons.get(response_type, "🤖")
        
        return f"""
        <div style="background: linear-gradient(135deg, #f8fafc, #e2e8f0); 
                   padding: 20px; border-radius: 12px; margin: 10px 0;
                   border-left: 4px solid #3b82f6; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
            
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <div style="display: flex; align-items: center;">
                    <span style="font-size: 1.2em; margin-right: 10px;">{icon}</span>
                    <strong style="color: #1e293b;">{response_type}</strong>
                </div>
                <span style="color: #64748b; font-size: 0.9em;">{timestamp}</span>
            </div>
            
            <div style="color: #374151; line-height: 1.6; white-space: pre-wrap;">
{content}
            </div>
        </div>
        """
    
    def get_suggested_questions(self) -> List[str]:
        """Get suggested questions for users"""
        return [
            "What are the latest APT trends?",
            "How can I detect ransomware attacks?",
            "Explain the MITRE ATT&CK framework",
            "What IOCs should I monitor?",
            "Recommend threat hunting strategies",
            "How to respond to a security incident?",
            "What are zero-day vulnerabilities?",
            "Explain supply chain attacks"
        ]
    
    def get_conversation_summary(self) -> str:
        """Get summary of conversation history"""
        if not self.conversation_history:
            return "No conversation history available."
        
        summary = f"**Conversation Summary** ({len(self.conversation_history)} messages)\n\n"
        
        for i, entry in enumerate(self.conversation_history[-5:], 1):  # Last 5 messages
            timestamp = entry['timestamp'][:19]  # Remove microseconds
            message = entry['user_message'][:100] + ("..." if len(entry['user_message']) > 100 else "")
            summary += f"{i}. [{timestamp}] {message}\n"
        
        return summary
