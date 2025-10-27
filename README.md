# SOC Demo Project 🔐

> A Security Operations Center simulation I built to learn about real-time threat detection and monitoring

**Author:** HITAM Major Project Group 4 (Nithin, Shreyash, Harish, Advaith)
**Course:** CSE (Cyber Security)  
**Date:** October 2025

---

## What is this?

So basically, I wanted to understand how a real Security Operations Center works. This project is like a mini SOC that:
- Collects security logs from different sources
- Analyzes them in real-time 
- Detects suspicious stuff (like brute force attacks, port scans, SQL injections)
- Sends alerts to Slack when something bad happens
- Shows everything in a nice dashboard

It's not production-ready or anything, but it helped me understand the concepts!

---

## Tech Stack

Here's what I used:

- **Elasticsearch** - Stores all the logs (think of it like a database but for searching logs really fast)
- **Kibana** - The web interface where you can visualize everything
- **Logstash** - Processes the logs before storing them
- **Docker** - Runs everything in containers so you don't mess up your system
- **Python** - For generating fake logs and sending alerts
- **Slack API** - For getting notifications when attacks are detected

---

## Prerequisites

You have two options to run this project:

### Option A: GitHub Codespaces (Recommended - What I Used!)

**This is what I used because Docker Desktop wasn't working on my Windows machine (Hyper-V issues).** Codespaces gives you a full Linux environment with Docker already installed!

1. **GitHub Account** (free)
2. **That's it!** Everything else is pre-installed in Codespaces

**Why Codespaces?**
- No local Docker installation needed
- Works on any computer (even Chromebooks!)
- 60 hours/month free
- Docker, Python, everything pre-installed
- Can access from anywhere

### Option B: Local Machine

If you want to run locally instead:

1. **Docker & Docker Compose** installed
   - Linux/Mac: Install Docker Engine
   - Windows Pro/Enterprise: Docker Desktop with WSL2
   - Windows Home: Good luck (or just use Codespaces lol)

2. **Python 3.8+**

3. **Git**

4. **A Slack workspace** (optional, but recommended for alerts)
   - It's free! Create one at https://slack.com

---

## Setup Guide (Step by Step)

### Option A: Using GitHub Codespaces (My Method)

**This is the easiest way and what I actually used:**

1. **Fork or clone this repo to your GitHub account**

2. **Open in Codespaces:**
   - Click the green `<> Code` button on the repo page
   - Click the `Codespaces` tab
   - Click `Create codespace on main`
   - Wait 30 seconds for it to load

3. **You're done with setup!** Docker, Python, Git - everything is ready!

Now skip to the "Set up Python virtual environment" section below.

### Option B: Using Local Machine

```bash
# Clone this repo
git clone https://github.com/yourusername/soc-demo.git
cd soc-demo
```

### 2. Set up Python virtual environment

Trust me, use a venv. It keeps everything clean and you won't mess up your system Python packages.

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# On Linux/Mac:
source venv/bin/activate

# On Windows (if you're using that):
venv\Scripts\activate

# You should see (venv) in your terminal now
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

**Don't have a requirements.txt?** No worries, just run:
```bash
pip install requests elasticsearch python-dotenv
```

### 4. Set up Slack webhook (optional but cool)

If you want Slack alerts:

1. Go to https://api.slack.com/messaging/webhooks
2. Create a new Slack app
3. Enable "Incoming Webhooks"
4. Add webhook to your workspace
5. Copy the webhook URL

Then create a `.env` file:
```bash
# Create .env file in project root
echo "SLACK_WEBHOOK_URL=your_webhook_url_here" > .env
```

**Important:** Never commit your `.env` file! It's already in `.gitignore` but just be careful.

### 5. Start Docker services

This will download and start Elasticsearch, Kibana, and Logstash:

```bash
docker-compose up -d
```

Wait like 2-3 minutes for everything to start. You can check status with:
```bash
docker-compose ps
```

All three services should show "Up" or "Up (healthy)"

### 6. Set up Kibana

Open your browser and go to: http://localhost:5601

First time setup:
1. Click "Explore on my own" (skip the welcome tour)
2. Open the menu (☰) → Click "Discover"
3. Click "Create a data view"
4. Set index pattern to: `soc-logs-*`
5. Select `@timestamp` as the time field
6. Save it!

Now you're ready to see logs!

---

## Running the Demo

You'll need 3 terminal windows open (all with venv activated):

### Terminal 1: Log Generator
```bash
source venv/bin/activate  # activate venv first!
python3 simulation/log_generator.py
```
This creates realistic security logs - both normal traffic and some suspicious stuff.

### Terminal 2: Slack Alerter (optional)
```bash
source venv/bin/activate
export SLACK_WEBHOOK_URL="your_webhook_url"  # or it'll read from .env
python3 automation/slack_alerter.py
```
This monitors Elasticsearch and sends Slack alerts when it detects threats.

### Terminal 3: Attack Simulator
```bash
source venv/bin/activate
python3 simulation/attack_simulator.py
```
This lets you simulate different types of attacks to see the alerts in action!

Try running option 4 to simulate all attack types at once. Pretty cool to see them pop up in Kibana and Slack!

---

## What I Learned

Building this taught me:

- How SOCs actually work in the real world
- The ELK stack (Elasticsearch, Logstash, Kibana) - it's industry standard
- How to detect different types of attacks
- Docker orchestration (running multiple services together)
- Python scripting for security automation
- API integrations (Slack)
- Why environment variables matter (security!)

The coolest part was seeing how fast Elasticsearch can search through thousands of logs. Like seriously, it's instant.

---

## Project Structure

```
soc-demo/
├── configs/
│   └── logstash/
│       └── pipeline/
│           └── logstash.conf       # Log processing rules
├── simulation/
│   ├── log_generator.py            # Generates fake security logs
│   └── attack_simulator.py         # Simulates different attacks
├── automation/
│   └── slack_alerter.py            # Monitors and sends alerts
├── docker-compose.yml              # Docker services config
├── .env                            # Your secrets (don't commit!)
├── .gitignore                      # Keeps secrets safe
└── README.md                       # You are here!
```

---

## Troubleshooting

**Docker containers won't start?**
- Make sure Docker Desktop is running
- Try: `docker-compose down` then `docker-compose up -d`

**Python import errors?**
- Did you activate the venv? `source venv/bin/activate`
- Install packages: `pip install requests elasticsearch`

**Can't connect to Elasticsearch?**
- Wait 2-3 minutes after starting docker-compose
- Check: `curl http://localhost:9200`

**Slack alerts not working?**
- Check your webhook URL is correct
- Make sure it's set: `echo $SLACK_WEBHOOK_URL`

---

## Future Improvements

Some ideas I want to add later:

- [ ] More attack types (XSS, DDoS, etc.)
- [ ] Machine learning for anomaly detection
- [ ] Geo-location tracking of IP addresses
- [ ] Better Kibana dashboards with graphs
- [ ] Email alerts in addition to Slack
- [ ] Database of known malicious IPs
- [ ] Response automation (auto-block IPs)

Feel free to fork and add your own features!

---

## Demo for Review

If you're reviewing this:

1. Start everything: `docker-compose up -d`
2. Open Kibana: http://localhost:5601
3. Run log generator in one terminal
4. Run attack simulator in another
5. Watch the logs appear in Kibana in real-time
6. See alerts trigger (in Slack if configured)

The whole demo takes about 5 minutes.

---

## Credits & Resources

Stuff that helped me build this:

- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Docker Docs](https://docs.docker.com/)
- [Requests Library](https://requests.readthedocs.io/)
- Various YouTube tutorials on SOC basics
- Stack Overflow (of course lol)

---

## License

This is just an educational project. Feel free to use it, modify it, learn from it, whatever. If it helps you understand SOC concepts better, that's awesome!

---

## Contact

If you have questions or suggestions, feel free to open an issue or reach out!

**Note:** This is a learning project and NOT meant for actual production use. Real SOCs are way more complex with proper security hardening, multiple data sources, correlation rules, etc. But this gives you the basic idea!

---

Made with ☕ and a lot of trial & error
