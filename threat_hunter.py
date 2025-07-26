"""
Automated Threat Hunting Module
Provides proactive threat detection, hunting queries, and behavioral analysis
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import json
import re
import random

logger = logging.getLogger(__name__)

class AutomatedThreatHunter:
    """Advanced automated threat hunting capabilities"""
    
    def __init__(self, database, ai_analyzer):
        self.database = database
        self.ai_analyzer = ai_analyzer
        self.logger = logging.getLogger(__name__)
        
        # Threat hunting rules and signatures
        self.hunting_rules = {
            'suspicious_domains': {
                'name': 'Suspicious Domain Detection',
                'description': 'Detects domains with suspicious characteristics',
                'patterns': [
                    r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}',  # IP-like domains
                    r'[a-z]{20,}\.com',  # Very long random domains
                    r'.*-[0-9]{4,}\..*',  # Domains with long number sequences
                    r'.*\.tk$|.*\.ml$|.*\.ga$|.*\.cf$',  # Suspicious TLDs
                ],
                'severity': 'medium'
            },
            
            'suspicious_ips': {
                'name': 'Malicious IP Detection',
                'description': 'Identifies potentially malicious IP addresses',
                'patterns': [
                    r'^10\.0\.0\.',  # Suspicious private IP usage in public contexts
                    r'^192\.168\.',  # Private IP in public IOCs
                    r'^172\.(1[6-9]|2[0-9]|3[01])\.',  # Private IP ranges
                ],
                'severity': 'high'
            },
            
            'apt_indicators': {
                'name': 'APT Behavior Detection', 
                'description': 'Detects Advanced Persistent Threat indicators',
                'keywords': [
                    'lateral movement', 'privilege escalation', 'persistence',
                    'command and control', 'c2', 'backdoor', 'implant',
                    'living off the land', 'fileless', 'memory resident'
                ],
                'severity': 'critical'
            },
            
            'ransomware_indicators': {
                'name': 'Ransomware Detection',
                'description': 'Identifies ransomware-related activities',
                'keywords': [
                    'encryption', 'ransom', 'bitcoin', 'cryptocurrency',
                    'file extension', 'shadow copies', 'vssadmin',
                    'bcdedit', 'wbadmin', 'recovery'
                ],
                'severity': 'critical'
            },
            
            'supply_chain': {
                'name': 'Supply Chain Attack Detection',
                'description': 'Detects supply chain compromise indicators',
                'keywords': [
                    'software update', 'third party', 'vendor compromise',
                    'dependency', 'package manager', 'npm', 'pypi',
                    'software distribution', 'certificate'
                ],
                'severity': 'high'
            }
        }
        
        # Behavioral analysis patterns
        self.behavioral_patterns = {
            'data_exfiltration': [
                'large data transfers', 'unusual network traffic',
                'compression tools', 'staging directories',
                'cloud storage uploads', 'external communications'
            ],
            
            'credential_harvesting': [
                'password dumping', 'credential theft', 'mimikatz',
                'lsass', 'sam database', 'ntds', 'kerberos'
            ],
            
            'reconnaissance': [
                'network scanning', 'port enumeration', 'directory listing',
                'system information', 'user enumeration', 'service discovery'
            ]
        }
    
    async def run_automated_hunt(self) -> Dict[str, Any]:
        """Run comprehensive automated threat hunting"""
        try:
            hunt_results = {
                'timestamp': datetime.now().isoformat(),
                'total_threats_analyzed': 0,
                'hunting_results': {},
                'behavioral_analysis': {},
                'recommendations': [],
                'risk_score': 0
            }
            
            # Get recent threats for analysis
            recent_threats = self.database.get_recent_threats(limit=100)
            hunt_results['total_threats_analyzed'] = len(recent_threats)
            
            if not recent_threats:
                hunt_results['hunting_results']['status'] = 'No threats to analyze'
                return hunt_results
            
            # Convert ThreatIntelItem objects to dictionaries
            threats_data = []
            for threat in recent_threats:
                if hasattr(threat, 'to_dict'):
                    threats_data.append(threat.to_dict())
                else:
                    threats_data.append(threat)
            
            # Run hunting rules
            for rule_id, rule in self.hunting_rules.items():
                hunt_results['hunting_results'][rule_id] = await self._apply_hunting_rule(
                    rule, threats_data
                )
            
            # Behavioral analysis
            hunt_results['behavioral_analysis'] = await self._analyze_behavioral_patterns(
                threats_data
            )
            
            # Generate recommendations
            hunt_results['recommendations'] = await self._generate_hunting_recommendations(
                hunt_results
            )
            
            # Calculate risk score
            hunt_results['risk_score'] = self._calculate_risk_score(hunt_results)
            
            return hunt_results
            
        except Exception as e:
            logger.error(f"Error in automated threat hunting: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': 'Hunt failed'
            }
    
    async def _apply_hunting_rule(self, rule: Dict, threats: List[Dict]) -> Dict:
        """Apply specific hunting rule to threats"""
        try:
            matches = []
            
            for threat in threats:
                threat_text = f"{threat.get('title', '')} {threat.get('description', '')}".lower()
                
                # Check patterns (for domain/IP rules)
                if 'patterns' in rule:
                    for pattern in rule['patterns']:
                        if re.search(pattern, threat_text, re.IGNORECASE):
                            matches.append({
                                'threat_id': threat.get('id'),
                                'threat_title': threat.get('title'),
                                'match_pattern': pattern,
                                'match_type': 'pattern',
                                'severity': rule['severity']
                            })
                
                # Check keywords (for behavioral rules)
                if 'keywords' in rule:
                    for keyword in rule['keywords']:
                        if keyword.lower() in threat_text:
                            matches.append({
                                'threat_id': threat.get('id'),
                                'threat_title': threat.get('title'),
                                'match_keyword': keyword,
                                'match_type': 'keyword', 
                                'severity': rule['severity']
                            })
            
            return {
                'rule_name': rule['name'],
                'description': rule['description'],
                'matches': matches,
                'match_count': len(matches),
                'severity': rule['severity']
            }
            
        except Exception as e:
            logger.error(f"Error applying hunting rule: {e}")
            return {
                'rule_name': rule.get('name', 'Unknown'),
                'error': str(e),
                'match_count': 0
            }
    
    async def _analyze_behavioral_patterns(self, threats: List[Dict]) -> Dict:
        """Analyze behavioral patterns in threats"""
        try:
            behavior_results = {}
            
            for behavior_type, indicators in self.behavioral_patterns.items():
                matches = []
                
                for threat in threats:
                    threat_text = f"{threat.get('title', '')} {threat.get('description', '')}".lower()
                    
                    for indicator in indicators:
                        if indicator.lower() in threat_text:
                            matches.append({
                                'threat_id': threat.get('id'),
                                'threat_title': threat.get('title'),
                                'behavior_indicator': indicator,
                                'confidence': random.uniform(0.6, 0.95)  # Simulated confidence
                            })
                
                behavior_results[behavior_type] = {
                    'indicators_found': len(matches),
                    'matches': matches[:5],  # Top 5 matches
                    'risk_level': 'high' if len(matches) > 5 else 'medium' if len(matches) > 2 else 'low'
                }
            
            return behavior_results
            
        except Exception as e:
            logger.error(f"Error in behavioral analysis: {e}")
            return {'error': str(e)}
    
    async def _generate_hunting_recommendations(self, hunt_results: Dict) -> List[str]:
        """Generate actionable threat hunting recommendations"""
        try:
            recommendations = []
            
            # Analyze hunting results
            total_matches = sum(
                result.get('match_count', 0) 
                for result in hunt_results.get('hunting_results', {}).values()
                if isinstance(result, dict)
            )
            
            if total_matches > 10:
                recommendations.extend([
                    "🚨 High threat activity detected - Consider elevating security posture",
                    "🔍 Implement additional monitoring for detected IOCs",
                    "📋 Review and update threat hunting playbooks",
                    "🤝 Coordinate with threat intelligence teams for context"
                ])
            
            # Behavioral analysis recommendations
            behavioral = hunt_results.get('behavioral_analysis', {})
            
            if any(b.get('risk_level') == 'high' for b in behavioral.values()):
                recommendations.extend([
                    "⚠️ High-risk behavioral patterns detected",
                    "🔐 Review access controls and privilege escalation vectors",
                    "📊 Enhance behavioral monitoring and anomaly detection",
                    "🎯 Consider targeted threat hunting campaigns"
                ])
            
            # General recommendations
            recommendations.extend([
                "📈 Monitor trending attack techniques and TTPs",
                "🛡️ Validate detection rules against recent threats",
                "📚 Update threat intelligence feeds and sources",
                "🔄 Schedule regular automated hunting runs"
            ])
            
            return recommendations[:8]  # Top 8 recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return ["❌ Error generating recommendations"]
    
    def _calculate_risk_score(self, hunt_results: Dict) -> float:
        """Calculate overall risk score based on hunting results"""
        try:
            base_score = 0.0
            
            # Score based on hunting rule matches
            hunting_results = hunt_results.get('hunting_results', {})
            for result in hunting_results.values():
                if isinstance(result, dict) and 'match_count' in result:
                    severity = result.get('severity', 'low')
                    match_count = result.get('match_count', 0)
                    
                    severity_multiplier = {
                        'critical': 10,
                        'high': 7,
                        'medium': 4,
                        'low': 1
                    }.get(severity, 1)
                    
                    base_score += match_count * severity_multiplier
            
            # Score based on behavioral analysis
            behavioral = hunt_results.get('behavioral_analysis', {})
            for behavior_result in behavioral.values():
                if isinstance(behavior_result, dict):
                    risk_level = behavior_result.get('risk_level', 'low')
                    indicators = behavior_result.get('indicators_found', 0)
                    
                    risk_multiplier = {
                        'high': 15,
                        'medium': 8,
                        'low': 3
                    }.get(risk_level, 1)
                    
                    base_score += indicators * risk_multiplier
            
            # Normalize to 0-100 scale
            max_possible_score = 1000  # Estimated maximum
            normalized_score = min((base_score / max_possible_score) * 100, 100)
            
            return round(normalized_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 0.0
    
    def get_hunting_queries(self) -> List[Dict]:
        """Get predefined threat hunting queries"""
        return [
            {
                'name': 'Suspicious Network Connections',
                'description': 'Hunt for unusual outbound connections',
                'query': 'network.protocol:tcp AND destination.port:(4444 OR 8080 OR 9999)',
                'category': 'Network'
            },
            {
                'name': 'Privilege Escalation Attempts',
                'description': 'Detect privilege escalation activities',
                'query': 'process.name:(whoami OR net OR runas) AND user.domain:*',
                'category': 'Endpoint'
            },
            {
                'name': 'Lateral Movement Indicators',
                'description': 'Hunt for lateral movement patterns',
                'query': 'process.name:(psexec OR wmic OR powershell) AND network.direction:outbound',
                'category': 'Network'
            },
            {
                'name': 'Data Staging Activities',
                'description': 'Detect potential data exfiltration staging',
                'query': 'file.extension:(zip OR rar OR 7z) AND file.size:>10MB',
                'category': 'File'
            },
            {
                'name': 'Suspicious PowerShell Activity',
                'description': 'Hunt for malicious PowerShell usage',
                'query': 'process.name:powershell AND process.args:(-enc OR -EncodedCommand OR downloadstring)',
                'category': 'Endpoint'
            }
        ]
