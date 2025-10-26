#!/usr/bin/env python3
"""
SOC Demo - Attack Simulator
"""

import requests
import json
import time
from datetime import datetime

LOGSTASH_URL = "http://localhost:5000"

def simulate_brute_force():
    print("\n🔨 SIMULATING: Brute Force Attack")
    print("   " + "-" * 50)
    
    for i in range(5):
        log = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "failed_login",
            "username": "admin",
            "source_ip": "203.0.113.45",
            "service": "ssh",
            "status": "failure",
            "attempts": i + 1,
            "message": f"Failed login attempt #{i+1}"
        }
        
        try:
            requests.post(LOGSTASH_URL, json=log, timeout=5)
            print(f"   ✅ Attempt {i+1}/5 sent")
            time.sleep(1)
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("   ⏳ Wait 10s for alert...\n")

def simulate_port_scan():
    print("\n🔍 SIMULATING: Port Scan")
    print("   " + "-" * 50)
    
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "port_scan",
        "source_ip": "198.51.100.78",
        "destination_ip": "192.168.1.1",
        "ports_scanned": 250,
        "status": "detected",
        "message": "Aggressive port scan"
    }
    
    try:
        requests.post(LOGSTASH_URL, json=log, timeout=5)
        print("   ✅ Port scan logged")
        print("   ⏳ Wait 10s for alert...\n")
    except Exception as e:
        print(f"   ❌ Error: {e}\n")

def simulate_sql_injection():
    print("\n💉 SIMULATING: SQL Injection")
    print("   " + "-" * 50)
    
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "sql_injection",
        "source_ip": "203.0.113.45",
        "target_url": "/api/login",
        "payload": "admin' OR '1'='1' --",
        "status": "blocked",
        "message": "SQL injection blocked"
    }
    
    try:
        requests.post(LOGSTASH_URL, json=log, timeout=5)
        print("   ✅ SQL injection logged")
        print("   ⏳ Wait 10s for alert...\n")
    except Exception as e:
        print(f"   ❌ Error: {e}\n")

def main():
    print("=" * 60)
    print("🎮 SOC ATTACK SIMULATOR")
    print("=" * 60)
    print("\n1. 🔨 Brute Force Attack")
    print("2. 🔍 Port Scan")
    print("3. 💉 SQL Injection")
    print("4. 🌊 All Attacks")
    print("0. ❌ Exit\n")
    
    while True:
        choice = input("Choose (0-4): ").strip()
        
        if choice == "1":
            simulate_brute_force()
        elif choice == "2":
            simulate_port_scan()
        elif choice == "3":
            simulate_sql_injection()
        elif choice == "4":
            print("\n🚀 Running all attacks...\n")
            simulate_brute_force()
            time.sleep(3)
            simulate_port_scan()
            time.sleep(3)
            simulate_sql_injection()
            print("\n✅ Done!\n")
        elif choice == "0":
            print("\n👋 Goodbye!\n")
            break
        else:
            print("❌ Invalid choice\n")

if __name__ == "__main__":
    main()