# ⬡ CyberRemedy SOC PLATFORM v1.0 
CyberRemedy is a self-hosted, Security Information and Event Management (SIEM) system. It provides enterprise-grade threat detection, automated response, and real-time monitoring on a single machine — no cloud subscription, no licence fees, and no external data leaving your network.
It was built to give small and medium-sized teams the same capabilities that large security operations centres use, including machine learning anomaly detection, MITRE ATT&CK mapping, SOAR playbooks, honeypots, and full log management.

# Installation & Setup

<pre><code>
git clone https://github.com/moon0deva/CyberRemedy.git
cd CyberRemedy
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
</code> </pre>

# Optional but Recommended To Installs

<pre><code>
sudo apt install arp-scan nmap          # faster asset discovery
sudo setcap cap_net_raw                 # arp-scan
pip install netifaces==0.11.0           # more accurate network interface detection
pip install yara-python==4.5.1          # native YARA scanning (falls back to pure-Python)

</code> </pre>

Server starting on http://127.0.0.1:8000

# Run in Background (Linux)

<pre><code>
nohup python3 main.py > cyberremedy.log 2>&1 &
echo $! > cyberremedy.pid    # save PID for later
kill $(cat cyberremedy.pid) # to kill/stop
</code> </pre>

# Run as a systemd Service (Auto-Start on Boot)

<pre><code> sudo nano /etc/systemd/system/cyberremedy.service </code></pre>

Paste the following (adjust paths to match your install):

<pre><code>
[Unit]
Description=CyberRemedy SOC Platform
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/path/to/CyberRemedy-v1   # PATH of the CyberRemedY
ExecStart=/path/to/CyberRemedy-v1/venv/bin/python3 main.py # PATH of the main.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
</code></pre>

# Log Ingestion — Syslog & Windows
<pre><code> ip addr show | grep 'inet ' | grep -v 127.0.0.1 </code></pre>

# rsyslog (Ubuntu/Debian/CentOS)
<pre><code>
sudo apt install rsyslog -y           # install if missing
echo '*.* @@SERVER_IP:5514' | sudo tee -a /etc/rsyslog.conf
sudo systemctl restart rsyslog </code></pre>

# syslog-ng
<pre><code>sudo apt install syslog-ng -y </code></pre>
Add to /etc/syslog-ng/syslog-ng.conf:
destination d_cr { tcp("SERVER_IP" port(5514)); };
log { source(s_src); destination(d_cr); };
<pre><code>sudo systemctl restart syslog-ng</code></pre>

# logger
<pre><code> logger -n SERVER_IP -P 5514 -T "Test from $(hostname)"</code> 
  
