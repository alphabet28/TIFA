"""
Advanced Threat Visualization and Analytics Module
Provides real-time threat mapping, geolocation analysis, and advanced visualizations
"""

import json
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
from typing import Dict, List, Any
import requests
import logging
from datetime import datetime, timedelta
import random

logger = logging.getLogger(__name__)

class ThreatVisualization:
    """Advanced threat visualization and analytics"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Sample country coordinates for demonstration
        self.country_coords = {
            'United States': {'lat': 39.8283, 'lon': -98.5795, 'code': 'US'},
            'China': {'lat': 35.8617, 'lon': 104.1954, 'code': 'CN'},
            'Russia': {'lat': 61.5240, 'lon': 105.3188, 'code': 'RU'},
            'North Korea': {'lat': 40.3399, 'lon': 127.5101, 'code': 'KP'},
            'Iran': {'lat': 32.4279, 'lon': 53.6880, 'code': 'IR'},
            'Germany': {'lat': 51.1657, 'lon': 10.4515, 'code': 'DE'},
            'United Kingdom': {'lat': 55.3781, 'lon': -3.4360, 'code': 'GB'},
            'France': {'lat': 46.2276, 'lon': 2.2137, 'code': 'FR'},
            'Japan': {'lat': 36.2048, 'lon': 138.2529, 'code': 'JP'},
            'Brazil': {'lat': -14.2350, 'lon': -51.9253, 'code': 'BR'},
            'India': {'lat': 20.5937, 'lon': 78.9629, 'code': 'IN'},
            'Unknown': {'lat': 0, 'lon': 0, 'code': 'XX'}
        }
    
    def create_threat_map(self, threats: List[Dict]) -> str:
        """Create interactive world threat map"""
        try:
            # Process threats to extract geographic data
            threat_data = []
            country_counts = {}
            
            for threat in threats:
                # Simulate geolocation from threat data
                country = self._extract_country_from_threat(threat)
                if country in country_counts:
                    country_counts[country] += 1
                else:
                    country_counts[country] = 1
                    
                coords = self.country_coords.get(country, self.country_coords['Unknown'])
                threat_data.append({
                    'country': country,
                    'lat': coords['lat'],
                    'lon': coords['lon'],
                    'count': country_counts[country],
                    'severity': threat.get('severity', 'unknown'),
                    'title': threat.get('title', 'Unknown Threat')[:50],
                    'source': threat.get('source', 'Unknown')
                })
            
            # Create the map
            fig = go.Figure()
            
            # Add threat markers
            for severity in ['critical', 'high', 'medium', 'low', 'unknown']:
                severity_data = [t for t in threat_data if t['severity'].lower() == severity]
                if not severity_data:
                    continue
                    
                color_map = {
                    'critical': '#dc2626',
                    'high': '#ea580c', 
                    'medium': '#d97706',
                    'low': '#059669',
                    'unknown': '#6b7280'
                }
                
                fig.add_trace(go.Scattergeo(
                    lon=[t['lon'] for t in severity_data],
                    lat=[t['lat'] for t in severity_data],
                    text=[f"{t['country']}<br>Threats: {t['count']}<br>Severity: {t['severity']}<br>Source: {t['source']}" 
                          for t in severity_data],
                    mode='markers',
                    marker=dict(
                        size=[min(max(t['count'] * 3, 8), 30) for t in severity_data],
                        color=color_map[severity],
                        opacity=0.8,
                        line=dict(width=2, color='white')
                    ),
                    name=f"{severity.title()} Severity",
                    hovertemplate="<b>%{text}</b><extra></extra>"
                ))
            
            fig.update_layout(
                title={
                    'text': '🌍 Global Threat Intelligence Map',
                    'x': 0.5,
                    'font': {'size': 24, 'color': '#1e293b'}
                },
                geo=dict(
                    projection_type='orthographic',
                    showland=True,
                    landcolor='rgb(243, 243, 243)',
                    coastlinecolor='rgb(204, 204, 204)',
                    showocean=True,
                    oceancolor='rgb(230, 245, 255)',
                    projection_rotation=dict(lon=0, lat=0, roll=0)
                ),
                height=600,
                margin=dict(t=80, b=0, l=0, r=0)
            )
            
            return fig.to_html(include_plotlyjs='cdn', div_id="threat-map")
            
        except Exception as e:
            logger.error(f"Error creating threat map: {e}")
            return "<div style='text-align: center; padding: 40px; color: #dc2626;'>⚠️ Error generating threat map</div>"
    
    def create_threat_timeline(self, threats: List[Dict]) -> str:
        """Create interactive threat timeline"""
        try:
            # Process threat data for timeline
            timeline_data = []
            
            for threat in threats:
                published = threat.get('published', datetime.now().isoformat())
                if isinstance(published, str):
                    try:
                        published_dt = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    except:
                        published_dt = datetime.now()
                else:
                    published_dt = published
                
                timeline_data.append({
                    'date': published_dt,
                    'title': threat.get('title', 'Unknown Threat'),
                    'severity': threat.get('severity', 'unknown'),
                    'source': threat.get('source', 'Unknown'),
                    'description': threat.get('description', '')[:100] + '...'
                })
            
            # Sort by date
            timeline_data.sort(key=lambda x: x['date'])
            
            # Create timeline chart
            df = pd.DataFrame(timeline_data)
            
            color_map = {
                'critical': '#dc2626',
                'high': '#ea580c',
                'medium': '#d97706', 
                'low': '#059669',
                'unknown': '#6b7280'
            }
            
            fig = px.scatter(df, 
                           x='date', 
                           y='severity',
                           color='severity',
                           size=[1]*len(df),
                           hover_data=['title', 'source', 'description'],
                           color_discrete_map=color_map,
                           title='📈 Threat Intelligence Timeline')
            
            fig.update_layout(
                height=400,
                title_font_size=20,
                title_x=0.5,
                xaxis_title="Time",
                yaxis_title="Severity Level"
            )
            
            return fig.to_html(include_plotlyjs='cdn', div_id="threat-timeline")
            
        except Exception as e:
            logger.error(f"Error creating timeline: {e}")
            return "<div style='text-align: center; padding: 40px; color: #dc2626;'>⚠️ Error generating timeline</div>"
    
    def create_severity_distribution(self, threats: List[Dict]) -> str:
        """Create severity distribution chart"""
        try:
            severity_counts = {}
            for threat in threats:
                severity = threat.get('severity', 'unknown').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            fig = go.Figure(data=[
                go.Pie(
                    labels=list(severity_counts.keys()),
                    values=list(severity_counts.values()),
                    hole=0.3,
                    marker_colors=['#dc2626', '#ea580c', '#d97706', '#059669', '#6b7280']
                )
            ])
            
            fig.update_layout(
                title={
                    'text': '🎯 Threat Severity Distribution',
                    'x': 0.5,
                    'font': {'size': 20}
                },
                height=400
            )
            
            return fig.to_html(include_plotlyjs='cdn', div_id="severity-chart")
            
        except Exception as e:
            logger.error(f"Error creating severity chart: {e}")
            return "<div style='text-align: center; padding: 40px; color: #dc2626;'>⚠️ Error generating chart</div>"
    
    def _extract_country_from_threat(self, threat: Dict) -> str:
        """Extract country information from threat data"""
        # Simple country extraction logic - could be enhanced with NLP
        title = threat.get('title', '').lower()
        description = threat.get('description', '').lower()
        text = f"{title} {description}"
        
        # Country detection patterns
        country_patterns = {
            'china': 'China',
            'chinese': 'China', 
            'russia': 'Russia',
            'russian': 'Russia',
            'north korea': 'North Korea',
            'iran': 'Iran',
            'iranian': 'Iran',
            'usa': 'United States',
            'america': 'United States',
            'germany': 'Germany',
            'german': 'Germany',
            'uk': 'United Kingdom',
            'britain': 'United Kingdom',
            'france': 'France',
            'french': 'France',
            'japan': 'Japan',
            'japanese': 'Japan',
            'brazil': 'Brazil',
            'india': 'India',
            'indian': 'India'
        }
        
        for pattern, country in country_patterns.items():
            if pattern in text:
                return country
        
        # Default to random selection for demo
        return random.choice(list(self.country_coords.keys())[:-1])  # Exclude 'Unknown'
