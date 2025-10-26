#!/usr/bin/env python3
"""
SOC Demo - Slack Alerter
Monitors Elasticsearch for security threats and sends Slack alerts
"""

import os
import requests
import json
import time
from datetime import datetime
from elasticsearch import Elasticsearch

# ⚠️ REPLACE THIS WITH YOUR SLACK WEBHOOK URL
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

ES_HOST = "http://localhost:9200"
INDEX_PATTERN = "soc-logs-*"
CHECK_INTERVAL = 10
FAILED_LOGIN_THRESHOLD = 3

def send_slack_alert(title, message, severity="warning"):
    severity_config = {
        "low": {"color": "#36a64f", "emoji": "ℹ️"},
        "warning": {"color": "#ff9900", "emoji": "⚠️"},
        "high": {"color": "#ff0000", "emoji": "🚨"},
        "critical": {"color": "#8B0000", "emoji": "🔥"}
    }
    
    config = severity_config.get(severity, severity_config["warning"])
    
    payload = {
        "attachments": [{
            "color": config["color"],
            "title": f"{config['emoji']} {title}",
            "text": message,
            "footer": "SOC Demo Alert System",
            "ts": int(time.time())
        }]
    }
    
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"✅ Alert sent: {title}")
            return True
        else:
            print(f"❌ Slack error: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def check_failed_logins(es):
    query = {
        "size": 0,
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
                    "min_doc_count": FAILED_LOGIN_THRESHOLD
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
            
            title = "Brute Force Attack Detected"
            message = f"*Source IP:* `{ip}`\n*Failed Attempts:* {count} in last minute"
            send_slack_alert(title, message, severity="high")
            
    except Exception as e:
        print(f"⚠️ Error: {e}")

def check_port_scans(es):
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
            
            title = "Port Scan Detected"
            message = f"*Source IP:* `{ip}`\n*Ports Scanned:* {ports}"
            send_slack_alert(title, message, severity="critical")
            
    except Exception as e:
        print(f"⚠️ Error: {e}")

def check_sql_injection(es):
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
            
            title = "SQL Injection Blocked"
            message = f"*Source IP:* `{ip}`\n*Target:* `{url}`"
            send_slack_alert(title, message, severity="critical")
            
    except Exception as e:
        print(f"⚠️ Error: {e}")

def main():
    if "YOUR_SLACK_WEBHOOK_URL_HERE" in SLACK_WEBHOOK_URL:
        print("\n❌ ERROR: Update SLACK_WEBHOOK_URL first!")
        print("Get it from: https://api.slack.com/messaging/webhooks\n")
        return
    
    print("\n🚀 SOC SLACK ALERTER - Starting...")
    print(f"📡 Monitoring: {ES_HOST}")
    print(f"⏱️  Interval: {CHECK_INTERVAL}s\n")
    
    try:
        es = Elasticsearch([ES_HOST])
        es.info()
        print("✅ Connected to Elasticsearch\n")
    except Exception as e:
        print(f"❌ Cannot connect: {e}\n")
        return
    
    send_slack_alert("SOC System Online", "Monitoring started", severity="low")
    
    try:
        while True:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"🔍 Checking at {timestamp}")
            
            check_failed_logins(es)
            check_port_scans(es)
            check_sql_injection(es)
            
            time.sleep(CHECK_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n✋ Stopping...")
        send_slack_alert("SOC System Offline", "Monitoring stopped", severity="low")

if __name__ == "__main__":
    main()