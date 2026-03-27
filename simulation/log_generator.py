#!/usr/bin/env python3
"""
SOC Demo - Log Generator
Generates realistic security logs and sends them to Logstash
"""

import requests
import json
import random
import time
from datetime import datetime

LOGSTASH_URL = "http://localhost:5000"

USERNAMES = ["admin", "john.doe", "jane.smith", "root", "user123", "guest", "developer"]
NORMAL_SOURCE_IPS = [
    # Public routable examples spread across major regions for baseline traffic
    "52.95.245.18",   # North America
    "3.112.45.201",   # Asia-Pacific
    "18.194.76.132",  # Europe
    "34.100.212.44"   # South America
]

SUSPICIOUS_SOURCE_IPS = [
    # Public routable examples used for higher-risk behaviors
    "91.240.118.172", # Europe
    "103.86.182.64",  # Asia-Pacific
    "45.227.255.206", # South America
    "196.251.85.11"   # Africa
]
SERVICES = ["ssh", "http", "ftp", "mysql", "rdp", "smtp"]

def generate_normal_log():
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "successful_login",
        "username": random.choice(USERNAMES),
        "source_ip": random.choice(NORMAL_SOURCE_IPS),
        "service": random.choice(SERVICES),
        "status": "success",
        "message": "User logged in successfully"
    }
    return log

def generate_failed_login():
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "failed_login",
        "username": random.choice(USERNAMES),
        "source_ip": random.choice(SUSPICIOUS_SOURCE_IPS),
        "service": "ssh",
        "status": "failure",
        "attempts": random.randint(3, 10),
        "message": "Multiple failed login attempts detected"
    }
    return log

def generate_port_scan():
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "port_scan",
        "source_ip": random.choice(SUSPICIOUS_SOURCE_IPS),
        "destination_ip": "192.168.1.1",
        "ports_scanned": random.randint(50, 500),
        "status": "detected",
        "message": "Port scanning activity detected"
    }
    return log

def generate_sql_injection():
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "sql_injection",
        "source_ip": random.choice(SUSPICIOUS_SOURCE_IPS),
        "target_url": "/api/users",
        "payload": "' OR '1'='1",
        "status": "blocked",
        "message": "SQL injection attempt blocked by WAF"
    }
    return log

def send_log(log):
    try:
        response = requests.post(
            LOGSTASH_URL,
            json=log,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        if response.status_code == 200:
            event_emoji = {
                "successful_login": "✅",
                "failed_login": "❌",
                "port_scan": "🔍",
                "sql_injection": "💉"
            }
            emoji = event_emoji.get(log['event_type'], "📝")
            print(f"{emoji} {log['event_type']} from {log.get('source_ip', 'N/A')}")
        else:
            print(f"⚠️ Failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error: {e}")

def main():
    print("=" * 60)
    print("🚀 SOC LOG GENERATOR - Starting...")
    print("=" * 60)
    print(f"📡 Sending to: {LOGSTASH_URL}")
    print("⏱️  Rate: 1 log every 2 seconds")
    print("🛑 Press Ctrl+C to stop")
    print("=" * 60 + "\n")
    
    log_count = 0
    
    try:
        while True:
            rand = random.random()
            
            if rand < 0.6:
                log = generate_normal_log()
            elif rand < 0.8:
                log = generate_failed_login()
            elif rand < 0.95:
                log = generate_port_scan()
            else:
                log = generate_sql_injection()
            
            send_log(log)
            log_count += 1
            
            if log_count % 10 == 0:
                print(f"\n📊 Total logs sent: {log_count}\n")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(f"\n\n{'=' * 60}")
        print(f"✋ Stopped. Total logs sent: {log_count}")
        print(f"{'=' * 60}")

if __name__ == "__main__":
    main()