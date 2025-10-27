#!/usr/bin/env python3
"""
SOC Demo - Enterprise-Grade Slack Alerter
Professional security alerts with comprehensive threat intelligence
"""

import os
import requests
import json
import time
from datetime import datetime
from elasticsearch import Elasticsearch
from typing import Dict, Optional, List
import hashlib

# Configuration
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
ES_HOST = "http://localhost:9200"
INDEX_PATTERN = "soc-logs-*"
CHECK_INTERVAL = 10
FAILED_LOGIN_THRESHOLD = 3

# Free Threat Intelligence APIs (no key required for basic lookups)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")  # Optional: Get free key at abuseipdb.com
IPAPI_URL = "http://ip-api.com/json/{}"  # Free geo-IP lookup


class ThreatIntelligence:
    """Threat intelligence enrichment"""
    
    @staticmethod
    def get_ip_geolocation(ip: str) -> Dict:
        """Get geographic information for IP address"""
        try:
            response = requests.get(IPAPI_URL.format(ip), timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'is_proxy': data.get('proxy', False),
                        'is_hosting': data.get('hosting', False)
                    }
        except Exception as e:
            print(f"⚠️ Geo lookup error: {e}")
        
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown'
        }
    
    @staticmethod
    def check_ip_reputation(ip: str) -> Dict:
        """Check IP reputation against threat databases"""
        reputation = {
            'is_known_bad': False,
            'threat_score': 0,
            'categories': [],
            'last_reported': None
        }
        
        # Check against AbuseIPDB if API key is provided
        if ABUSEIPDB_API_KEY:
            try:
                headers = {
                    'Key': ABUSEIPDB_API_KEY,
                    'Accept': 'application/json'
                }
                params = {'ipAddress': ip, 'maxAgeInDays': 90}
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params,
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    reputation['is_known_bad'] = data.get('abuseConfidenceScore', 0) > 50
                    reputation['threat_score'] = data.get('abuseConfidenceScore', 0)
                    reputation['categories'] = data.get('usageType', 'Unknown')
                    reputation['last_reported'] = data.get('lastReportedAt')
            except Exception as e:
                print(f"⚠️ AbuseIPDB lookup error: {e}")
        
        # Simple heuristic checks (without API)
        if ip.startswith(('203.', '198.51.100.', '192.0.2.')):
            reputation['is_known_bad'] = True
            reputation['threat_score'] = 75
            reputation['categories'] = ['Suspicious Range']
        
        return reputation
    
    @staticmethod
    def get_attack_classification(event_type: str) -> Dict:
        """Classify attack according to MITRE ATT&CK framework"""
        classifications = {
            'failed_login': {
                'mitre_tactic': 'TA0006 - Credential Access',
                'mitre_technique': 'T1110 - Brute Force',
                'severity': 'HIGH',
                'risk_score': 75
            },
            'port_scan': {
                'mitre_tactic': 'TA0043 - Reconnaissance',
                'mitre_technique': 'T1046 - Network Service Scanning',
                'severity': 'MEDIUM',
                'risk_score': 60
            },
            'sql_injection': {
                'mitre_tactic': 'TA0001 - Initial Access',
                'mitre_technique': 'T1190 - Exploit Public-Facing Application',
                'severity': 'CRITICAL',
                'risk_score': 95
            },
            'malware_detected': {
                'mitre_tactic': 'TA0002 - Execution',
                'mitre_technique': 'T1204 - User Execution',
                'severity': 'CRITICAL',
                'risk_score': 90
            },
            'data_exfiltration': {
                'mitre_tactic': 'TA0010 - Exfiltration',
                'mitre_technique': 'T1041 - Exfiltration Over C2 Channel',
                'severity': 'CRITICAL',
                'risk_score': 85
            }
        }
        
        return classifications.get(event_type, {
            'mitre_tactic': 'Unknown',
            'mitre_technique': 'Unknown',
            'severity': 'MEDIUM',
            'risk_score': 50
        })


class EnterpriseSlackAlerter:
    """Enterprise-grade Slack alert formatting"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.alert_history = set()  # Track sent alerts to avoid duplicates
    
    def _generate_alert_id(self, alert_data: Dict) -> str:
        """Generate unique ID for alert deduplication"""
        unique_string = f"{alert_data.get('event_type')}_{alert_data.get('source_ip')}_{alert_data.get('timestamp')}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:8]
    
    def _get_severity_config(self, severity: str) -> Dict:
        """Get color coding and emojis for severity levels"""
        configs = {
            "LOW": {"color": "#36a64f", "emoji": "ℹ️", "priority": "P4"},
            "MEDIUM": {"color": "#ff9900", "emoji": "⚠️", "priority": "P3"},
            "HIGH": {"color": "#ff0000", "emoji": "🚨", "priority": "P2"},
            "CRITICAL": {"color": "#8B0000", "emoji": "🔥", "priority": "P1"}
        }
        return configs.get(severity, configs["MEDIUM"])
    
    def send_comprehensive_alert(self, alert_data: Dict, threat_intel: Dict, classification: Dict) -> bool:
        """Send detailed enterprise-style Slack alert"""
        
        # Check for duplicate alerts
        alert_id = self._generate_alert_id(alert_data)
        if alert_id in self.alert_history:
            return False  # Skip duplicate
        
        severity = classification.get('severity', 'MEDIUM')
        config = self._get_severity_config(severity)
        
        # Build comprehensive alert
        blocks = [
            # Header
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{config['emoji']} Security Alert: {alert_data.get('title', 'Security Incident')}",
                    "emoji": True
                }
            },
            
            # Alert Summary
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Alert ID:*\n`{alert_id}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{config['emoji']} *{severity}* ({config['priority']})"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{classification.get('risk_score', 50)}/100"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Event Type:*\n{alert_data.get('event_type', 'Unknown')}"
                    }
                ]
            },
            
            {"type": "divider"},
            
            # Threat Details
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🎯 Threat Details*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Source IP:*\n`{alert_data.get('source_ip', 'Unknown')}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Target:*\n{alert_data.get('target', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Count/Volume:*\n{alert_data.get('count', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Timestamp:*\n{alert_data.get('timestamp', datetime.now().isoformat())}"
                    }
                ]
            },
            
            {"type": "divider"},
            
            # Geographic Intelligence
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🌍 Geographic Intelligence*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Location:*\n{threat_intel['geo'].get('city', 'Unknown')}, {threat_intel['geo'].get('region', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Country:*\n:flag-{threat_intel['geo'].get('country_code', 'xx').lower()}: {threat_intel['geo'].get('country', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*ISP/Organization:*\n{threat_intel['geo'].get('isp', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Timezone:*\n{threat_intel['geo'].get('timezone', 'Unknown')}"
                    }
                ]
            },
            
            # Additional indicators
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Proxy/VPN:*\n{'🔴 Yes' if threat_intel['geo'].get('is_proxy') else '🟢 No'}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Hosting Provider:*\n{'🔴 Yes' if threat_intel['geo'].get('is_hosting') else '🟢 No'}"
                    }
                ]
            },
            
            {"type": "divider"},
            
            # Threat Intelligence
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🛡️ Threat Intelligence*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Known Malicious:*\n{'🔴 YES' if threat_intel['reputation']['is_known_bad'] else '🟢 NO'}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Threat Score:*\n{threat_intel['reputation']['threat_score']}/100"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Categories:*\n{', '.join(threat_intel['reputation']['categories']) if threat_intel['reputation']['categories'] else 'None'}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Last Reported:*\n{threat_intel['reputation']['last_reported'] or 'Never'}"
                    }
                ]
            },
            
            {"type": "divider"},
            
            # MITRE ATT&CK Classification
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*⚔️ MITRE ATT&CK Framework*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Tactic:*\n{classification.get('mitre_tactic', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Technique:*\n{classification.get('mitre_technique', 'Unknown')}"
                    }
                ]
            },
            
            {"type": "divider"},
            
            # Recommended Actions
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🎯 Recommended Actions*\n{alert_data.get('recommendations', self._get_default_recommendations(alert_data.get('event_type')))}"
                }
            },
            
            {"type": "divider"},
            
            # Additional Context (if available)
        ]
        
        # Add event-specific details
        if alert_data.get('additional_details'):
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*📋 Additional Details*\n{alert_data['additional_details']}"
                }
            })
            blocks.append({"type": "divider"})
        
        # Action Buttons
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "🔍 Investigate in Kibana"
                    },
                    "url": f"http://localhost:5601/app/discover#/?_a=(query:(language:kuery,query:'source.ip:\"{alert_data.get('source_ip', '')}\"'))",
                    "style": "primary"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "🔒 Block IP"
                    },
                    "style": "danger",
                    "value": f"block_{alert_data.get('source_ip', '')}"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "📊 View Full Report"
                    },
                    "url": "http://localhost:5601"
                }
            ]
        })
        
        # Footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🤖 *SOC Demo Alert System* | Detection Engine: Elasticsearch | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
            ]
        })
        
        # Send to Slack
        payload = {
            "blocks": blocks,
            "attachments": [{
                "color": config["color"],
                "fallback": f"{severity} Alert: {alert_data.get('title', 'Security Incident')}"
            }]
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                self.alert_history.add(alert_id)
                print(f"✅ Alert {alert_id} sent: {alert_data.get('title')}")
                return True
            else:
                print(f"❌ Slack error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Error sending alert: {e}")
            return False
    
    def _get_default_recommendations(self, event_type: str) -> str:
        """Get default recommendations based on event type"""
        recommendations = {
            'failed_login': (
                "• Immediately block source IP at firewall\n"
                "• Force password reset for targeted accounts\n"
                "• Enable MFA if not already configured\n"
                "• Review access logs for successful logins from this IP\n"
                "• Check for other failed login attempts from this source"
            ),
            'port_scan': (
                "• Block source IP at network perimeter\n"
                "• Review firewall rules for unnecessary open ports\n"
                "• Check for any successful connections from this IP\n"
                "• Enable IDS/IPS if not active\n"
                "• Review network segmentation"
            ),
            'sql_injection': (
                "• Immediately block source IP\n"
                "• Review application logs for successful injections\n"
                "• Patch vulnerable application code\n"
                "• Enable WAF if not configured\n"
                "• Audit database for unauthorized changes\n"
                "• Review input validation mechanisms"
            ),
            'malware_detected': (
                "• Isolate infected system from network immediately\n"
                "• Run full antivirus scan\n"
                "• Review process list for suspicious activity\n"
                "• Check for persistence mechanisms\n"
                "• Image system for forensic analysis\n"
                "• Restore from known good backup if compromised"
            ),
            'data_exfiltration': (
                "• Immediately isolate affected system\n"
                "• Block destination IP/domain\n"
                "• Review data access logs\n"
                "• Identify compromised accounts\n"
                "• Contact legal/compliance team\n"
                "• Preserve evidence for investigation"
            )
        }
        
        return recommendations.get(event_type, (
            "• Investigate the incident immediately\n"
            "• Document all findings\n"
            "• Escalate to security team if needed\n"
            "• Review related logs for additional IOCs"
        ))


def check_failed_logins(es: Elasticsearch, alerter: EnterpriseSlackAlerter):
    """Monitor for brute force attacks with comprehensive alerting"""
    query = {
        "size": 10,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "failed_login"}},
                    {"range": {"@timestamp": {"gte": "now-1m"}}}
                ]
            }
        },
        "aggs": {
            "failed_by_ip": {
                "terms": {
                    "field": "source_ip.keyword",
                    "min_doc_count": FAILED_LOGIN_THRESHOLD,
                    "size": 10
                },
                "aggs": {
                    "target_users": {
                        "terms": {"field": "target_user.keyword", "size": 5}
                    },
                    "latest_attempt": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": {"order": "desc"}}]
                        }
                    }
                }
            }
        }
    }
    
    try:
        result = es.search(index=INDEX_PATTERN, body=query)
        buckets = result["aggregations"]["failed_by_ip"]["buckets"]
        
        for bucket in buckets:
            ip = bucket["key"]
            count = bucket["doc_count"]
            target_users = [b["key"] for b in bucket["target_users"]["buckets"]]
            latest = bucket["latest_attempt"]["hits"]["hits"][0]["_source"]
            
            # Get threat intelligence
            ti = ThreatIntelligence()
            geo_data = ti.get_ip_geolocation(ip)
            reputation = ti.check_ip_reputation(ip)
            classification = ti.get_attack_classification('failed_login')
            
            # Build alert data
            alert_data = {
                'title': 'Brute Force Attack Detected',
                'event_type': 'failed_login',
                'source_ip': ip,
                'target': ', '.join(target_users[:3]) + (f' (+{len(target_users)-3} more)' if len(target_users) > 3 else ''),
                'count': f"{count} failed attempts in last minute",
                'timestamp': latest.get('@timestamp', datetime.now().isoformat()),
                'additional_details': (
                    f"• Attack started: {bucket['latest_attempt']['hits']['hits'][0]['_source'].get('@timestamp', 'Unknown')}\n"
                    f"• Targeted users: {', '.join(target_users)}\n"
                    f"• Attack still in progress: {'Yes' if count > FAILED_LOGIN_THRESHOLD else 'No'}\n"
                    f"• Service: {latest.get('service', 'Unknown')}"
                )
            }
            
            threat_intel = {
                'geo': geo_data,
                'reputation': reputation
            }
            
            alerter.send_comprehensive_alert(alert_data, threat_intel, classification)
            
    except Exception as e:
        print(f"⚠️ Error checking failed logins: {e}")


def check_port_scans(es: Elasticsearch, alerter: EnterpriseSlackAlerter):
    """Monitor for port scanning activity"""
    query = {
        "size": 1,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "port_scan"}},
                    {"range": {"@timestamp": {"gte": "now-30s"}}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    
    try:
        result = es.search(index=INDEX_PATTERN, body=query)
        
        if result["hits"]["total"]["value"] > 0:
            hit = result["hits"]["hits"][0]["_source"]
            ip = hit.get("source_ip", "Unknown")
            ports = hit.get("ports_scanned", "Unknown")
            
            ti = ThreatIntelligence()
            geo_data = ti.get_ip_geolocation(ip)
            reputation = ti.check_ip_reputation(ip)
            classification = ti.get_attack_classification('port_scan')
            
            alert_data = {
                'title': 'Port Scan Detected - Reconnaissance Activity',
                'event_type': 'port_scan',
                'source_ip': ip,
                'target': hit.get("target_host", "Unknown"),
                'count': f"{ports} ports scanned",
                'timestamp': hit.get('@timestamp', datetime.now().isoformat()),
                'additional_details': (
                    f"• Scan type: {hit.get('scan_type', 'Unknown')}\n"
                    f"• Duration: {hit.get('scan_duration', 'Unknown')}\n"
                    f"• Open ports found: {hit.get('open_ports', 'None')}"
                ),
                'recommendations': (
                    "• Block source IP immediately\n"
                    "• Review firewall rules for unnecessary open ports\n"
                    "• Check for successful connections from this IP\n"
                    "• This is often reconnaissance before an attack\n"
                    "• Monitor this IP for follow-up attack attempts"
                )
            }
            
            threat_intel = {'geo': geo_data, 'reputation': reputation}
            alerter.send_comprehensive_alert(alert_data, threat_intel, classification)
            
    except Exception as e:
        print(f"⚠️ Error checking port scans: {e}")


def check_sql_injection(es: Elasticsearch, alerter: EnterpriseSlackAlerter):
    """Monitor for SQL injection attempts"""
    query = {
        "size": 1,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "sql_injection"}},
                    {"range": {"@timestamp": {"gte": "now-30s"}}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    
    try:
        result = es.search(index=INDEX_PATTERN, body=query)
        
        if result["hits"]["total"]["value"] > 0:
            hit = result["hits"]["hits"][0]["_source"]
            ip = hit.get("source_ip", "Unknown")
            url = hit.get("target_url", "Unknown")
            payload = hit.get("injection_payload", "Unknown")
            
            ti = ThreatIntelligence()
            geo_data = ti.get_ip_geolocation(ip)
            reputation = ti.check_ip_reputation(ip)
            classification = ti.get_attack_classification('sql_injection')
            
            alert_data = {
                'title': 'SQL Injection Attack Blocked',
                'event_type': 'sql_injection',
                'source_ip': ip,
                'target': url,
                'count': "1 injection attempt",
                'timestamp': hit.get('@timestamp', datetime.now().isoformat()),
                'additional_details': (
                    f"• Injection payload: `{payload[:100]}...`\n"
                    f"• Attack successful: {'🔴 YES' if hit.get('success') else '🟢 NO (Blocked)'}\n"
                    f"• User agent: {hit.get('user_agent', 'Unknown')}\n"
                    f"• HTTP method: {hit.get('http_method', 'Unknown')}"
                )
            }
            
            threat_intel = {'geo': geo_data, 'reputation': reputation}
            alerter.send_comprehensive_alert(alert_data, threat_intel, classification)
            
    except Exception as e:
        print(f"⚠️ Error checking SQL injection: {e}")


def main():
    """Main monitoring loop"""
    if not SLACK_WEBHOOK_URL or "YOUR_SLACK_WEBHOOK_URL_HERE" in SLACK_WEBHOOK_URL:
        print("\n❌ ERROR: SLACK_WEBHOOK_URL environment variable not set!")
        print("Get your webhook URL from: https://api.slack.com/messaging/webhooks")
        print("\nSet it with:")
        print('  export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"\n')
        return
    
    print("\n" + "="*70)
    print("🚀 SOC ENTERPRISE SLACK ALERTER - Starting...")
    print("="*70)
    print(f"📡 Elasticsearch: {ES_HOST}")
    print(f"📊 Index Pattern: {INDEX_PATTERN}")
    print(f"⏱️  Check Interval: {CHECK_INTERVAL}s")
    print(f"🔐 Failed Login Threshold: {FAILED_LOGIN_THRESHOLD}")
    print("="*70 + "\n")
    
    # Connect to Elasticsearch
    try:
        es = Elasticsearch([ES_HOST])
        es.info()
        print("✅ Connected to Elasticsearch")
        print(f"✅ Cluster: {es.info()['cluster_name']}")
        print(f"✅ Version: {es.info()['version']['number']}\n")
    except Exception as e:
        print(f"❌ Cannot connect to Elasticsearch: {e}\n")
        return
    
    # Initialize alerter
    alerter = EnterpriseSlackAlerter(SLACK_WEBHOOK_URL)
    
    # Send startup notification
    startup_alert = {
        'title': 'SOC Monitoring System Online',
        'event_type': 'system_status',
        'source_ip': 'localhost',
        'target': 'All Systems',
        'count': 'N/A',
        'timestamp': datetime.now().isoformat(),
        'additional_details': (
            f"• Monitoring started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"• Elasticsearch cluster: {es.info()['cluster_name']}\n"
            f"• Check interval: {CHECK_INTERVAL} seconds\n"
            f"• Active detections: Brute Force, Port Scans, SQL Injection"
        )
    }
    
    classification = {'severity': 'LOW', 'risk_score': 0, 'mitre_tactic': 'N/A', 'mitre_technique': 'N/A'}
    threat_intel = {
        'geo': {'country': 'N/A', 'city': 'N/A', 'isp': 'N/A', 'country_code': 'xx'},
        'reputation': {'is_known_bad': False, 'threat_score': 0, 'categories': [], 'last_reported': None}
    }
    
    print("📢 Sending startup notification to Slack...")
    alerter.send_comprehensive_alert(startup_alert, threat_intel, classification)
    print()
    
    # Main monitoring loop
    try:
        print("🔍 Monitoring started. Press Ctrl+C to stop.\n")
        
        while True:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"🔍 [{timestamp}] Checking for threats...")
            
            check_failed_logins(es, alerter)
            check_port_scans(es, alerter)
            check_sql_injection(es, alerter)
            
            time.sleep(CHECK_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n\n" + "="*70)
        print("✋ Stopping monitoring...")
        print("="*70 + "\n")
        
        # Send shutdown notification
        shutdown_alert = {
            'title': 'SOC Monitoring System Offline',
            'event_type': 'system_status',
            'source_ip': 'localhost',
            'target': 'All Systems',
            'count': 'N/A',
            'timestamp': datetime.now().isoformat(),
            'additional_details': (
                f"• Monitoring stopped at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"• Total alerts sent this session: {len(alerter.alert_history)}\n"
                f"• System status: Graceful shutdown"
            )
        }
        
        alerter.send_comprehensive_alert(shutdown_alert, threat_intel, classification)
        print("✅ Shutdown notification sent")
        print("\n👋 SOC Alerter stopped successfully\n")


if __name__ == "__main__":
    main()