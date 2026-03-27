#!/usr/bin/env python3
import requests
import json
import random
import time
from datetime import datetime

LOGSTASH_URL = "http://localhost:5000"

# Global attack sources with realistic geo-data
ATTACK_SOURCES = [
    {"ip": "103.124.105.{}",  "country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "isp": "China Telecom"},
    {"ip": "185.220.101.{}",  "country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "isp": "Rostelecom"},
    {"ip": "45.142.212.{}",   "country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234, "isp": "PE Skurykhin Mukola Volodumurovuch"},
    {"ip": "203.0.113.{}",    "country": "North Korea", "city": "Pyongyang", "lat": 39.0392, "lon": 125.7625, "isp": "Star JV"},
    {"ip": "198.51.100.{}",   "country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890, "isp": "Telecommunication Company of Iran"},
    {"ip": "91.215.153.{}",   "country": "Romania", "city": "Bucharest", "lat": 44.4268, "lon": 26.1025, "isp": "Orange Romania"},
    {"ip": "177.85.64.{}",    "country": "Brazil", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333, "isp": "Vivo"},
    {"ip": "41.191.238.{}",   "country": "Nigeria", "city": "Lagos", "lat": 6.5244, "lon": 3.3792, "isp": "MTN Nigeria"},
    {"ip": "202.137.10.{}",   "country": "Indonesia", "city": "Jakarta", "lat": -6.2088, "lon": 106.8456, "isp": "Telkom Indonesia"},
    {"ip": "89.248.174.{}",   "country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "isp": "KPN"},
]

# Legitimate sources
LEGITIMATE_SOURCES = [
    {"ip": "192.168.1.{}",    "country": "Internal", "city": "Office Network", "lat": 0, "lon": 0, "isp": "Internal"},
    {"ip": "10.0.0.{}",       "country": "Internal", "city": "Data Center", "lat": 0, "lon": 0, "isp": "Internal"},
    {"ip": "172.16.0.{}",     "country": "Internal", "city": "VPN Pool", "lat": 0, "lon": 0, "isp": "Internal"},
    {"ip": "8.8.8.{}",        "country": "USA", "city": "Mountain View", "lat": 37.4220, "lon": -122.0841, "isp": "Google"},
    {"ip": "1.1.1.{}",        "country": "USA", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "Cloudflare"},
]

# Attack types with MITRE ATT&CK
ATTACK_TYPES = [
    {
        "type": "failed_login",
        "severity": "high",
        "mitre_tactic": "TA0006 - Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "description": "Multiple failed authentication attempts"
    },
    {
        "type": "port_scan",
        "severity": "medium",
        "mitre_tactic": "TA0043 - Reconnaissance",
        "mitre_technique": "T1046 - Network Service Scanning",
        "description": "Port scanning activity detected"
    },
    {
        "type": "sql_injection",
        "severity": "critical",
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "description": "SQL injection attack attempt"
    },
    {
        "type": "malware_detected",
        "severity": "critical",
        "mitre_tactic": "TA0002 - Execution",
        "mitre_technique": "T1204 - User Execution",
        "description": "Malicious software detected"
    },
    {
        "type": "data_exfiltration",
        "severity": "critical",
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1041 - Exfiltration Over C2",
        "description": "Suspicious data transfer detected"
    },
    {
        "type": "ddos_attack",
        "severity": "high",
        "mitre_tactic": "TA0040 - Impact",
        "mitre_technique": "T1499 - Endpoint Denial of Service",
        "description": "DDoS attack in progress"
    },
    {
        "type": "privilege_escalation",
        "severity": "high",
        "mitre_tactic": "TA0004 - Privilege Escalation",
        "mitre_technique": "T1068 - Exploitation for Privilege Escalation",
        "description": "Unauthorized privilege escalation attempt"
    },
    {
        "type": "ransomware",
        "severity": "critical",
        "mitre_tactic": "TA0040 - Impact",
        "mitre_technique": "T1486 - Data Encrypted for Impact",
        "description": "Ransomware encryption activity"
    }
]

NORMAL_ACTIVITIES = ["web_access", "file_transfer", "email_send", "database_query", "api_request"]
SERVICES = ["http", "https", "ssh", "ftp", "smtp", "mysql", "rdp", "dns"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "curl/7.68.0",
    "Python-requests/2.28.1",
    "PostmanRuntime/7.29.2"
]

def generate_attack_log():
    """Generate realistic attack log"""
    source = random.choice(ATTACK_SOURCES)
    attack = random.choice(ATTACK_TYPES)
    
    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": attack["type"],
        "severity": attack["severity"],
        "source_ip": source["ip"].format(random.randint(1, 254)),
        "source_port": random.randint(1024, 65535),
        "destination_ip": f"192.168.1.{random.randint(1, 254)}",
        "destination_port": random.choice([22, 80, 443, 3306, 3389, 8080]),
        "protocol": random.choice(["TCP", "UDP"]),
        "service": random.choice(SERVICES),
        "user_agent": random.choice(USER_AGENTS),
        
        # Geo data
        "geoip": {
            "country_name": source["country"],
            "city_name": source["city"],
            "location": {
                "lat": source["lat"],
                "lon": source["lon"]
            },
            "continent_name": "Asia" if source["country"] in ["China", "North Korea", "Iran", "Indonesia"] else "Europe"
        },
        "source_isp": source["isp"],
        
        # MITRE ATT&CK
        "mitre_tactic": attack["mitre_tactic"],
        "mitre_technique": attack["mitre_technique"],
        
        # Attack-specific fields
        "message": attack["description"],
        "blocked": random.choice([True, False]),
        "detection_engine": "Sigma" if random.random() > 0.5 else "Suricata"
    }
    
    # Add type-specific fields
    if attack["type"] == "failed_login":
        log["failed_attempts"] = random.randint(5, 25)
        log["target_username"] = random.choice(["admin", "root", "user", "administrator"])
    elif attack["type"] == "port_scan":
        log["ports_scanned"] = random.randint(50, 1000)
        log["scan_duration"] = random.randint(5, 300)
    elif attack["type"] == "sql_injection":
        log["injection_payload"] = random.choice(["' OR '1'='1", "admin'--", "1' UNION SELECT NULL--"])
        log["target_url"] = random.choice(["/login", "/api/users", "/admin/panel"])
    elif attack["type"] == "malware_detected":
        log["malware_family"] = random.choice(["Emotet", "TrickBot", "Ryuk", "Cobalt Strike"])
        log["file_hash"] = ''.join(random.choices('0123456789abcdef', k=64))
    elif attack["type"] == "data_exfiltration":
        log["data_size_mb"] = random.randint(100, 5000)
        log["protocol"] = "HTTPS"
    
    return log

def generate_normal_log():
    """Generate normal activity log"""
    source = random.choice(LEGITIMATE_SOURCES)
    
    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": random.choice(NORMAL_ACTIVITIES),
        "severity": "info",
        "source_ip": source["ip"].format(random.randint(1, 254)),
        "source_port": random.randint(1024, 65535),
        "destination_ip": f"192.168.1.{random.randint(1, 254)}",
        "destination_port": random.choice([80, 443, 53, 25]),
        "protocol": "TCP",
        "service": random.choice(SERVICES),
        "user_agent": random.choice(USER_AGENTS),
        
        # Geo data
        "geoip": {
            "country_name": source["country"],
            "city_name": source["city"],
            "location": {
                "lat": source["lat"],
                "lon": source["lon"]
            }
        },
        "source_isp": source["isp"],
        
        "message": "Normal activity",
        "blocked": False,
        "detection_engine": "N/A"
    }
    
    return log

def send_log(log):
    """Send log to Logstash"""
    try:
        response = requests.post(
            LOGSTASH_URL,
            json=log,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        if response.status_code == 200:
            emoji = "🚨" if log["severity"] in ["high", "critical"] else "✅"
            print(f"{emoji} {log['event_type']:20} | {log['source_ip']:20} | {log['geoip']['country_name']:15} | {log['severity'].upper()}")
            return True
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("=" * 100)
    print("🌍 ENHANCED SOC LOG GENERATOR - Professional Global Simulation")
    print("=" * 100)
    print(f"📡 Target: {LOGSTASH_URL}")
    print(f"🌐 Simulating traffic from {len(ATTACK_SOURCES)} countries")
    print(f"⚔️  Attack types: {len(ATTACK_TYPES)}")
    print(f"⏱️  Rate: ~30 logs/minute (1 every 2 seconds)")
    print("=" * 100)
    print(f"{'Event Type':<20} | {'Source IP':<20} | {'Country':<15} | Severity")
    print("-" * 100)
    
    stats = {"total": 0, "attacks": 0, "normal": 0}
    
    try:
        while True:
            # 20% attacks, 80% normal
            if random.random() < 0.2:
                log = generate_attack_log()
                stats["attacks"] += 1
            else:
                log = generate_normal_log()
                stats["normal"] += 1
            
            if send_log(log):
                stats["total"] += 1
            
            # Print stats every 50 logs
            if stats["total"] % 50 == 0:
                print("-" * 100)
                print(f"📊 Stats: Total: {stats['total']} | Normal: {stats['normal']} | Attacks: {stats['attacks']} | Attack Rate: {stats['attacks']/stats['total']*100:.1f}%")
                print("-" * 100)
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n" + "=" * 100)
        print("✋ Stopped")
        print(f"📊 Final Stats: {stats}")
        print("=" * 100)

if __name__ == "__main__":
    main()