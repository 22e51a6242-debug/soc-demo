#!/usr/bin/env python3
"""
SOC Demo - ML Anomaly Detection
Uses Isolation Forest to detect suspicious behavior patterns
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import json
from datetime import datetime
from elasticsearch import Elasticsearch
import os

ES_HOST = "http://localhost:9200"
INDEX_PATTERN = "soc-logs-*"
MODEL_PATH = "ml-models/anomaly_model.pkl"
SCALER_PATH = "ml-models/scaler.pkl"
METRICS_PATH = "ml-models/training_metrics.json"

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.es = Elasticsearch([ES_HOST])
        
    def fetch_training_data(self, days=7):
        """Fetch logs from Elasticsearch for training"""
        print(f"📥 Fetching {days} days of logs from Elasticsearch...")
        
        query = {
            "size": 10000,
            "query": {
                "range": {
                    "@timestamp": {"gte": f"now-{days}d"}
                }
            }
        }
        
        try:
            result = self.es.search(index=INDEX_PATTERN, body=query)
            hits = result['hits']['hits']
            print(f"✅ Retrieved {len(hits)} log entries")
            return hits
        except Exception as e:
            print(f"⚠️ Error fetching data: {e}")
            return []
    
    def extract_features(self, logs):
        """Extract numerical features from logs"""
        print("🔧 Extracting features from logs...")
        
        features = []
        for log in logs:
            source = log['_source']
            
            # Extract features (convert everything to numbers)
            feature_vector = {
                'hour': datetime.fromisoformat(source.get('@timestamp', '2024-01-01T00:00:00').replace('Z', '')).hour,
                'is_failed_login': 1 if source.get('event_type') == 'failed_login' else 0,
                'is_port_scan': 1 if source.get('event_type') == 'port_scan' else 0,
                'is_sql_injection': 1 if source.get('event_type') == 'sql_injection' else 0,
                'is_external_ip': 1 if source.get('source_ip', '').startswith(('203.', '198.', '192.0')) else 0,
                'attempts': source.get('attempts', 0),
                'ports_scanned': source.get('ports_scanned', 0)
            }
            features.append(feature_vector)
        
        df = pd.DataFrame(features)
        print(f"✅ Extracted {len(df)} feature vectors with {len(df.columns)} features")
        print(f"📊 Features: {list(df.columns)}")
        return df
    
    def train_model(self, X):
        """Train Isolation Forest model"""
        print("\n🎓 Training Isolation Forest model...")
        print(f"   Training samples: {len(X)}")
        print(f"   Contamination rate: 10% (expected anomalies)")
        
        # Normalize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=0.1,  # 10% of data is anomalous
            n_estimators=100,
            max_samples=256,
            random_state=42
        )
        
        print("   Training in progress...")
        self.model.fit(X_scaled)
        print("✅ Model training complete!")
        
        # Calculate training metrics
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        anomalies = np.sum(predictions == -1)
        normal = np.sum(predictions == 1)
        
        metrics = {
            'training_date': datetime.now().isoformat(),
            'training_samples': len(X),
            'features': list(X.columns),
            'model': 'Isolation Forest',
            'contamination': 0.1,
            'n_estimators': 100,
            'anomalies_detected': int(anomalies),
            'normal_samples': int(normal),
            'anomaly_rate': float(anomalies / len(X)),
            'mean_anomaly_score': float(scores.mean()),
            'min_score': float(scores.min()),
            'max_score': float(scores.max())
        }
        
        return metrics
    
    def save_model(self, metrics):
        """Save trained model and metrics"""
        os.makedirs('ml-models', exist_ok=True)
        
        print("\n💾 Saving model...")
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        
        with open(METRICS_PATH, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"✅ Model saved to: {MODEL_PATH}")
        print(f"✅ Scaler saved to: {SCALER_PATH}")
        print(f"✅ Metrics saved to: {METRICS_PATH}")
    
    def load_model(self):
        """Load pre-trained model"""
        print("📂 Loading pre-trained model...")
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        print("✅ Model loaded successfully")
    
    def detect_anomalies(self, new_logs):
        """Detect anomalies in new logs"""
        if not self.model:
            print("❌ Model not trained! Run training first.")
            return
        
        print(f"\n🔍 Analyzing {len(new_logs)} new logs for anomalies...")
        
        features = self.extract_features(new_logs)
        X_scaled = self.scaler.transform(features)
        
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:  # Anomaly detected
                log = new_logs[i]['_source']
                anomalies.append({
                    'log': log,
                    'anomaly_score': float(score),
                    'severity': 'HIGH' if score < -0.5 else 'MEDIUM'
                })
        
        print(f"🚨 Detected {len(anomalies)} anomalies out of {len(new_logs)} logs")
        return anomalies
    
    def print_training_summary(self, metrics):
        """Print nice training summary"""
        print("\n" + "="*70)
        print("📊 MODEL TRAINING SUMMARY")
        print("="*70)
        print(f"Training Date:        {metrics['training_date']}")
        print(f"Algorithm:            {metrics['model']}")
        print(f"Training Samples:     {metrics['training_samples']}")
        print(f"Features Used:        {len(metrics['features'])}")
        print(f"  └─ {', '.join(metrics['features'])}")
        print(f"\nDetection Results:")
        print(f"  Normal Samples:     {metrics['normal_samples']}")
        print(f"  Anomalies Detected: {metrics['anomalies_detected']}")
        print(f"  Anomaly Rate:       {metrics['anomaly_rate']:.1%}")
        print(f"\nModel Performance:")
        print(f"  Mean Anomaly Score: {metrics['mean_anomaly_score']:.4f}")
        print(f"  Score Range:        {metrics['min_score']:.4f} to {metrics['max_score']:.4f}")
        print("="*70)
        print("✅ Model is ready for real-time anomaly detection!")
        print("="*70 + "\n")


def train_mode():
    """Training mode - train new model"""
    detector = AnomalyDetector()
    
    # Fetch data
    logs = detector.fetch_training_data(days=7)
    
    if len(logs) < 100:
        print("\n⚠️ Not enough training data!")
        print("   Run log_generator.py for a few minutes first.")
        return
    
    # Extract features
    features = detector.extract_features(logs)
    
    # Train model
    metrics = detector.train_model(features)
    
    # Save everything
    detector.save_model(metrics)
    
    # Print summary
    detector.print_training_summary(metrics)


def detection_mode():
    """Detection mode - use trained model on new logs"""
    detector = AnomalyDetector()
    
    try:
        detector.load_model()
    except FileNotFoundError:
        print("❌ No trained model found! Run training mode first.")
        return
    
    print("🔍 Real-time anomaly detection mode")
    print("Checking logs every 30 seconds...")
    print("Press Ctrl+C to stop\n")
    
    import time
    
    try:
        while True:
            # Fetch recent logs
            query = {
                "size": 100,
                "query": {
                    "range": {"@timestamp": {"gte": "now-1m"}}
                },
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            result = detector.es.search(index=INDEX_PATTERN, body=query)
            recent_logs = result['hits']['hits']
            
            if recent_logs:
                anomalies = detector.detect_anomalies(recent_logs)
                
                if anomalies:
                    print(f"\n🚨 ANOMALIES DETECTED:")
                    for anom in anomalies:
                        log = anom['log']
                        print(f"   ⚠️ {log.get('event_type')} from {log.get('source_ip')}")
                        print(f"      Score: {anom['anomaly_score']:.4f} | Severity: {anom['severity']}")
            
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n\n✋ Stopped anomaly detection")


def main():
    print("="*70)
    print("🤖 SOC ML ANOMALY DETECTION SYSTEM")
    print("="*70)
    print("\n1. 🎓 Train New Model (run once with existing logs)")
    print("2. 🔍 Real-time Anomaly Detection (continuous monitoring)")
    print("3. 📊 View Training Metrics")
    print("0. ❌ Exit\n")
    
    choice = input("Choose mode (0-3): ").strip()
    
    if choice == "1":
        train_mode()
    elif choice == "2":
        detection_mode()
    elif choice == "3":
        try:
            with open(METRICS_PATH, 'r') as f:
                metrics = json.load(f)
            detector = AnomalyDetector()
            detector.print_training_summary(metrics)
        except FileNotFoundError:
            print("❌ No training metrics found! Train model first.")
    elif choice == "0":
        print("\n👋 Goodbye!\n")
    else:
        print("❌ Invalid choice")


if __name__ == "__main__":
    main()