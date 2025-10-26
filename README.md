# soc-demo
Security Operations Center Demo Project
# SOC Demo Project 🔐

**Security Operations Center Demo - Real-time Threat Detection System**

**Author:** [Your Name]  
**Course:** [Your Course/Subject]  
**Date:** October 2025

## 🎯 Project Overview

This project demonstrates a complete Security Operations Center (SOC) infrastructure with:
- Real-time log collection and analysis
- Automated threat detection
- Slack alert notifications
- Interactive Kibana dashboards

## 🛠️ Technology Stack

- **Elasticsearch** - Log storage and search
- **Kibana** - Visualization dashboard
- **Logstash** - Log processing pipeline
- **Docker** - Containerization
- **Python** - Log generation and alerting
- **Slack API** - Real-time notifications

## 🚀 Quick Start
```bash
# Start all services
docker-compose up -d

# Generate logs
python3 simulation/log_generator.py

# Run alerter (after configuring Slack webhook)
python3 automation/slack_alerter.py

# Simulate attacks
python3 simulation/attack_simulator.py
```

## 📊 Access Points

- **Kibana Dashboard:** http://localhost:5601
- **Elasticsearch API:** http://localhost:9200
- **Logstash Input:** http://localhost:5000

## 🎓 Learning Outcomes

- Understanding SOC architecture
- Log aggregation and analysis
- Security event detection
- Automation and alerting
- Docker orchestration

## 📝 Future Enhancements

- [ ] Add more attack types
- [ ] Implement machine learning detection
- [ ] Add geolocation tracking
- [ ] Create custom Kibana visualizations
- [ ] Integrate with SIEM tools

## 📄 License

Educational project - feel free to use and modify!