#!/usr/bin/env python3
"""
AI-Based Behavioral Monitoring System for SSH Sessions
Integrates with Dynamic Port Knocking System

This system monitors SSH user behavior in real-time and blacklists users
who exhibit malicious command patterns based on ML models trained on SSH attack data.
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any
import pickle
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
import warnings
import torch
from transformers import BertTokenizer, BertModel
warnings.filterwarnings('ignore')

# Add the partb-2nd directory to the path to import utilities
sys.path.append(os.path.join(os.path.dirname(__file__), 'partb-2nd', 'scripts'))

try:
    from data_processing import sample_data_by_label_combinations
    from plotting_utils import save_plot
except ImportError:
    print("Warning: Could not import partb-2nd utilities. Some features may be limited.")

# Add intent class names (order must match training)
intent_classes = [
    'Defense Evasion', 'Discovery', 'Execution', 'Harmless', 'Impact', 'Other', 'Persistence'
]

class CustomBERTModel(torch.nn.Module):
    def __init__(self, num_labels=7):
        super().__init__()
        self.bert = BertModel.from_pretrained('bert-base-uncased')
        self.classifier = torch.nn.Linear(self.bert.config.hidden_size, num_labels)
    def forward(self, input_ids, attention_mask, token_type_ids=None):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask, token_type_ids=token_type_ids)
        cls_output = outputs.last_hidden_state[:, 0, :]
        logits = self.classifier(cls_output)
        return logits

class BehavioralMonitor:
    """
    AI-based behavioral monitoring system for SSH sessions.
    Monitors user commands and blacklists users exhibiting malicious behavior.
    """
    
    def __init__(self, config_path: str = "monitor_config.json"):
        """Initialize the behavioral monitoring system."""
        self.config = self._load_config(config_path)
        self.setup_logging()
        
        # Initialize data structures
        self.user_sessions = defaultdict(lambda: {
            'commands': deque(maxlen=self.config['max_session_commands']),
            'session_start': None,
            'risk_score': 0.0,
            'blacklisted': False,
            'last_activity': None,
            'command_history': [],
            'suspicious_patterns': []
        })
        
        # Load ML models and preprocessing
        self.models = {}
        self.vectorizer = None
        self.feature_names = []
        self.load_ml_models()
        
        # Initialize monitoring
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Blacklist management
        self.blacklist = set()
        self.blacklist_file = self.config['blacklist_file']
        self.load_blacklist()
        
        # Statistics
        self.stats = {
            'total_sessions': 0,
            'blacklisted_users': 0,
            'suspicious_commands': 0,
            'false_positives': 0
        }
        
        self.logger.info("Behavioral Monitor initialized successfully")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        default_config = {
            'log_file': 'behavioral_monitor.log',
            'log_level': 'INFO',
            'blacklist_file': 'blacklisted_users.json',
            'model_dir': 'partb-2nd/results/models',
            'max_session_commands': 1000,
            'risk_threshold': 0.7,
            'command_window_size': 10,
            'session_timeout_minutes': 30,
            'update_interval_seconds': 5,
            'ssh_log_file': '/var/log/auth.log',
            'enable_real_time_monitoring': True,
            'enable_blacklisting': True,
            'notification_webhook': None,
            'backup_interval_hours': 24
        }
        
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            self._create_default_config(config_path, default_config)
        
        return default_config
    
    def _create_default_config(self, config_path: str, config: Dict[str, Any]):
        """Create default configuration file."""
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Created default configuration file: {config_path}")
    
    def setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.config['log_level']),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('BehavioralMonitor')
    
    def load_ml_models(self):
        """Load custom BERT model and tokenizer for SSH command intent classification, handling _orig_mod. prefix in state_dict."""
        try:
            model_path = os.path.join(os.path.dirname(__file__), 'Model', 'final_model.pth')
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
            self.bert_model = CustomBERTModel(num_labels=7)
            state_dict = torch.load(model_path, map_location=self.device)
            # Remove _orig_mod. prefix if present
            new_state_dict = {}
            for k, v in state_dict.items():
                if k.startswith('_orig_mod.'):
                    new_k = k[len('_orig_mod.'):]
                else:
                    new_k = k
                new_state_dict[new_k] = v
            self.bert_model.load_state_dict(new_state_dict)
            self.bert_model.to(self.device)
            self.bert_model.eval()
            self.logger.info("Loaded custom BERT model and tokenizer for SSH command intent classification")
        except Exception as e:
            self.bert_model = None
            self.tokenizer = None
            self.logger.error(f"Error loading custom BERT model: {e}")
            self.logger.info("Falling back to rule-based detection")
    
    def preprocess_commands(self, commands: List[str]) -> str:
        """Preprocess commands for ML model input."""
        # Clean and tokenize commands similar to partb-2nd preprocessing
        cleaned_commands = []
        
        for cmd in commands:
            # Remove special characters but keep paths
            cmd = cmd.strip()
            if cmd:
                # Basic cleaning similar to partb-2nd
                cmd = cmd.replace(';', ' ').replace('|', ' ')
                cmd = ' '.join(cmd.split())  # Normalize whitespace
                cleaned_commands.append(cmd)
        
        return ' '.join(cleaned_commands)
    
    def extract_features(self, commands: List[str]) -> np.ndarray:
        """Extract features from commands using TF-IDF vectorizer."""
        if not self.vectorizer:
            return np.array([])
        
        try:
            # Preprocess commands
            command_text = self.preprocess_commands(commands)
            
            # Transform using TF-IDF
            features = self.vectorizer.transform([command_text])
            return features.toarray()
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return np.array([])
    
    def predict_malicious_intent(self, commands: List[str]) -> Tuple[float, str]:
        """Predict malicious intent using custom BERT model (multi-label)."""
        if not hasattr(self, 'bert_model') or self.bert_model is None or self.tokenizer is None:
            return self._rule_based_detection(commands)
        try:
            command_text = self.preprocess_commands(commands)
            inputs = self.tokenizer(command_text, return_tensors='pt', truncation=True, padding=True, max_length=128)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            with torch.no_grad():
                logits = self.bert_model(**inputs)
                probs = torch.sigmoid(logits).cpu().numpy()[0]  # shape: (7,)
            # Harmless is index 3; all others are malicious
            malicious_indices = [i for i, name in enumerate(intent_classes) if name != 'Harmless']
            malicious_probs = probs[malicious_indices]
            max_prob = float(malicious_probs.max())
            max_intent = intent_classes[malicious_indices[malicious_probs.argmax()]]
            return max_prob, f'bert_{max_intent}'
        except Exception as e:
            self.logger.error(f"Error in BERT prediction: {e}")
            return self._rule_based_detection(commands)
    
    def _rule_based_detection(self, commands: List[str]) -> Tuple[float, str]:
        """Rule-based detection as fallback when ML models are unavailable."""
        malicious_patterns = {
            'system_reconnaissance': [
                'cat /proc/cpuinfo', 'cat /proc/mounts', 'uname -a', 'lscpu',
                'cat /etc/passwd', 'cat /etc/shadow', 'ps aux', 'netstat',
                'ss -tuln', 'lsof', 'who', 'w', 'last'
            ],
            'privilege_escalation': [
                'sudo', 'su', 'chmod +s', 'chown', 'passwd', 'chpasswd',
                'visudo', 'id', 'whoami'
            ],
            'persistence': [
                'crontab', 'systemctl', 'service', 'chkconfig', 'rc.local',
                'init.d', 'systemd', 'cron', 'at'
            ],
            'data_exfiltration': [
                'scp', 'rsync', 'nc', 'netcat', 'wget', 'curl', 'ftp',
                'sftp', 'tar', 'zip', 'gzip'
            ],
            'defense_evasion': [
                'history -c', 'rm -rf', 'shred', 'dd', 'echo "" >',
                'truncate', 'chattr +i', 'chattr -i'
            ]
        }
        
        risk_score = 0.0
        detected_patterns = []
        
        command_text = ' '.join(commands).lower()
        
        for pattern_type, patterns in malicious_patterns.items():
            for pattern in patterns:
                if pattern in command_text:
                    risk_score += 0.2  # Increment risk for each pattern
                    detected_patterns.append(f"{pattern_type}: {pattern}")
        
        # Normalize risk score to 0-1 range
        risk_score = min(risk_score, 1.0)
        
        return risk_score, f"rule_based_{len(detected_patterns)}_patterns"
    
    def analyze_user_behavior(self, username: str, command: str) -> Dict[str, Any]:
        """Analyze a single command from a user."""
        user_data = self.user_sessions[username]
        
        # Update session data
        user_data['commands'].append(command)
        user_data['last_activity'] = datetime.now()
        
        if not user_data['session_start']:
            user_data['session_start'] = datetime.now()
        
        # Analyze command window
        command_window = list(user_data['commands'])[-self.config['command_window_size']:]
        
        # Get ML prediction
        risk_score, model_used = self.predict_malicious_intent(command_window)
        
        # Update user risk score (exponential moving average)
        alpha = 0.3
        user_data['risk_score'] = alpha * risk_score + (1 - alpha) * user_data['risk_score']
        
        # Check for immediate blacklisting
        if risk_score > self.config['risk_threshold']:
            user_data['suspicious_patterns'].append({
                'timestamp': datetime.now(),
                'command': command,
                'risk_score': risk_score,
                'model_used': model_used
            })
            
            if self.config['enable_blacklisting']:
                self.blacklist_user(username, f"High risk command detected: {command}")
        
        return {
            'username': username,
            'command': command,
            'risk_score': risk_score,
            'cumulative_risk': user_data['risk_score'],
            'model_used': model_used,
            'blacklisted': user_data['blacklisted'],
            'session_duration': (datetime.now() - user_data['session_start']).total_seconds() if user_data['session_start'] else 0
        }
    
    def blacklist_user(self, username: str, reason: str):
        """Blacklist a user and take action."""
        if username in self.blacklist:
            return  # Already blacklisted
        
        self.blacklist.add(username)
        self.user_sessions[username]['blacklisted'] = True
        self.stats['blacklisted_users'] += 1
        
        # Log the blacklisting
        self.logger.warning(f"User {username} blacklisted. Reason: {reason}")
        
        # Take action (block SSH access)
        self._block_ssh_access(username)
        
        # Save blacklist
        self.save_blacklist()
        
        # Send notification if configured
        if self.config['notification_webhook']:
            self._send_notification(username, reason)
    
    def _block_ssh_access(self, username: str):
        """Block SSH access for blacklisted user."""
        try:
            # Method 1: Use iptables to block the user's IP
            # This would require tracking IP addresses, which we'll implement later
            
            # Method 2: Use fail2ban or similar
            # subprocess.run(['fail2ban-client', 'set', 'sshd', 'banip', ip_address])
            
            # Method 3: Modify SSH configuration to deny access
            # This is a placeholder for now
            
            self.logger.info(f"SSH access blocked for user: {username}")
            
        except Exception as e:
            self.logger.error(f"Error blocking SSH access for {username}: {e}")
    
    def _send_notification(self, username: str, reason: str):
        """Send notification about blacklisted user."""
        try:
            # Placeholder for webhook notification
            notification = {
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'reason': reason,
                'action': 'blacklisted'
            }
            
            # Here you would send to webhook, email, etc.
            self.logger.info(f"Notification sent for blacklisted user: {username}")
            
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}")
    
    def load_blacklist(self):
        """Load blacklist from file."""
        try:
            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, 'r') as f:
                    data = json.load(f)
                    self.blacklist = set(data.get('blacklisted_users', []))
                self.logger.info(f"Loaded {len(self.blacklist)} blacklisted users")
        except Exception as e:
            self.logger.error(f"Error loading blacklist: {e}")
    
    def save_blacklist(self):
        """Save blacklist to file."""
        try:
            data = {
                'blacklisted_users': list(self.blacklist),
                'last_updated': datetime.now().isoformat()
            }
            with open(self.blacklist_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error saving blacklist: {e}")
    
    def start_monitoring(self):
        """Start real-time monitoring."""
        if self.monitoring_active:
            self.logger.warning("Monitoring is already active")
            return
        
        self.monitoring_active = True
        
        if self.config['enable_real_time_monitoring']:
            self.monitor_thread = threading.Thread(target=self._monitor_ssh_logs, daemon=True)
            self.monitor_thread.start()
            self.logger.info("Started real-time SSH log monitoring")
        
        # Start session cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_sessions, daemon=True)
        cleanup_thread.start()
        
        self.logger.info("Behavioral monitoring system started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Behavioral monitoring system stopped")
    
    def _monitor_ssh_logs(self):
        """Monitor SSH logs in real-time."""
        log_file = self.config['ssh_log_file']
        
        if not os.path.exists(log_file):
            self.logger.error(f"SSH log file not found: {log_file}")
            return
        
        try:
            # Use tail to follow the log file
            process = subprocess.Popen(
                ['tail', '-f', log_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in process.stdout:
                if not self.monitoring_active:
                    break
                
                self._process_ssh_log_line(line)
                
        except Exception as e:
            self.logger.error(f"Error monitoring SSH logs: {e}")
        finally:
            if process:
                process.terminate()
    
    def _process_ssh_log_line(self, line: str):
        """Process a single SSH log line."""
        try:
            # Parse SSH log line to extract username and command
            # This is a simplified parser - you may need to adjust based on your log format
            
            if 'Accepted password' in line or 'Accepted publickey' in line:
                # User login
                parts = line.split()
                if len(parts) >= 9:
                    username = parts[8]
                    self._handle_user_login(username)
            
            elif 'session opened' in line:
                # Session opened
                parts = line.split()
                if len(parts) >= 11:
                    username = parts[10]
                    self._handle_session_opened(username)
            
            elif 'session closed' in line:
                # Session closed
                parts = line.split()
                if len(parts) >= 11:
                    username = parts[10]
                    self._handle_session_closed(username)
            
            # Note: Command execution is harder to capture from auth.log
            # You might need to use auditd or other tools for command monitoring
            
        except Exception as e:
            self.logger.error(f"Error processing SSH log line: {e}")
    
    def _handle_user_login(self, username: str):
        """Handle user login event."""
        if username in self.blacklist:
            self.logger.warning(f"Blacklisted user {username} attempted to login")
            # You could take additional action here
    
    def _handle_session_opened(self, username: str):
        """Handle session opened event."""
        self.user_sessions[username]['session_start'] = datetime.now()
        self.user_sessions[username]['last_activity'] = datetime.now()
        self.stats['total_sessions'] += 1
        self.logger.info(f"Session opened for user: {username}")
    
    def _handle_session_closed(self, username: str):
        """Handle session closed event."""
        if username in self.user_sessions:
            session_duration = datetime.now() - self.user_sessions[username]['session_start']
            self.logger.info(f"Session closed for user: {username}, duration: {session_duration}")
    
    def _cleanup_sessions(self):
        """Clean up old sessions."""
        while self.monitoring_active:
            try:
                timeout = timedelta(minutes=self.config['session_timeout_minutes'])
                current_time = datetime.now()
                
                users_to_remove = []
                for username, user_data in self.user_sessions.items():
                    if (user_data['last_activity'] and 
                        current_time - user_data['last_activity'] > timeout):
                        users_to_remove.append(username)
                
                for username in users_to_remove:
                    del self.user_sessions[username]
                    self.logger.info(f"Cleaned up session for user: {username}")
                
                time.sleep(self.config['update_interval_seconds'])
                
            except Exception as e:
                self.logger.error(f"Error in session cleanup: {e}")
                time.sleep(60)  # Wait longer on error
    
    def get_user_status(self, username: str) -> Dict[str, Any]:
        """Get current status of a user."""
        if username not in self.user_sessions:
            return {'username': username, 'status': 'unknown'}
        
        user_data = self.user_sessions[username]
        return {
            'username': username,
            'blacklisted': user_data['blacklisted'],
            'risk_score': user_data['risk_score'],
            'session_start': user_data['session_start'].isoformat() if user_data['session_start'] else None,
            'last_activity': user_data['last_activity'].isoformat() if user_data['last_activity'] else None,
            'command_count': len(user_data['commands']),
            'suspicious_patterns': len(user_data['suspicious_patterns'])
        }
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics."""
        return {
            'total_sessions': self.stats['total_sessions'],
            'blacklisted_users': self.stats['blacklisted_users'],
            'suspicious_commands': self.stats['suspicious_commands'],
            'false_positives': self.stats['false_positives'],
            'active_sessions': len(self.user_sessions),
            'blacklist_size': len(self.blacklist),
            'models_loaded': len(self.models)
        }
    
    def remove_from_blacklist(self, username: str):
        """Remove user from blacklist."""
        if username in self.blacklist:
            self.blacklist.remove(username)
            if username in self.user_sessions:
                self.user_sessions[username]['blacklisted'] = False
            self.save_blacklist()
            self.logger.info(f"User {username} removed from blacklist")
    
    def test_command(self, username: str, command: str) -> Dict[str, Any]:
        """Test a command without affecting user session."""
        return self.analyze_user_behavior(username, command)


def main():
    """Main function to run the behavioral monitor."""
    import argparse
    
    parser = argparse.ArgumentParser(description='AI-Based SSH Behavioral Monitor')
    parser.add_argument('--config', default='monitor_config.json', help='Configuration file path')
    parser.add_argument('--test', help='Test a command for a user')
    parser.add_argument('--user', help='Username for testing')
    parser.add_argument('--status', help='Get status of a user')
    parser.add_argument('--stats', action='store_true', help='Show system statistics')
    parser.add_argument('--blacklist', help='Add user to blacklist')
    parser.add_argument('--unblacklist', help='Remove user from blacklist')
    
    args = parser.parse_args()
    
    # Initialize monitor
    monitor = BehavioralMonitor(args.config)
    
    if args.test and args.user:
        # Test mode
        result = monitor.test_command(args.user, args.test)
        print(f"Test Result: {json.dumps(result, indent=2)}")
    
    elif args.status:
        # Status mode
        status = monitor.get_user_status(args.status)
        print(f"User Status: {json.dumps(status, indent=2)}")
    
    elif args.stats:
        # Stats mode
        stats = monitor.get_system_stats()
        print(f"System Statistics: {json.dumps(stats, indent=2)}")
    
    elif args.blacklist:
        # Blacklist mode
        monitor.blacklist_user(args.blacklist, "Manual blacklisting")
        print(f"User {args.blacklist} blacklisted")
    
    elif args.unblacklist:
        # Unblacklist mode
        monitor.remove_from_blacklist(args.unblacklist)
        print(f"User {args.unblacklist} removed from blacklist")
    
    else:
        # Start monitoring
        try:
            monitor.start_monitoring()
            print("Behavioral monitoring started. Press Ctrl+C to stop.")
            
            # Keep the main thread alive
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping behavioral monitoring...")
            monitor.stop_monitoring()
            print("Behavioral monitoring stopped.")


if __name__ == "__main__":
    main() 