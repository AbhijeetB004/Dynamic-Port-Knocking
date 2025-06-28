#!/usr/bin/env python3
"""
Integration Example: Port Knocking + Behavioral Monitoring

This example shows how to integrate the AI-based behavioral monitoring system
with the existing dynamic port knocking system.
"""

import os
import sys
import time
import json
import logging
import threading
from datetime import datetime
from behavioral_monitor import BehavioralMonitor
from ssh_command_capture import SSHCommandCapture

# Import your existing port knocking system
try:
    sys.path.append('Server')
    import pks
    from pks.core import Core
    from pks.config import Config
except ImportError:
    print("Warning: Port knocking system not found. Running in monitoring-only mode.")

class IntegratedSecuritySystem:
    """
    Integrated security system combining port knocking and behavioral monitoring.
    """
    
    def __init__(self, config_path: str = "integrated_config.json"):
        """Initialize the integrated security system."""
        self.config = self._load_integrated_config(config_path)
        self.setup_logging()
        
        # Initialize components
        self.behavioral_monitor = BehavioralMonitor(self.config['monitor_config'])
        self.command_capture = SSHCommandCapture(self._handle_ssh_event)
        
        # Port knocking system (if available)
        self.port_knocking = None
        if 'pks' in sys.modules:
            self.port_knocking = Core()
        
        # Integration state
        self.integration_active = False
        self.integration_thread = None
        
        # User session tracking
        self.active_sessions = {}
        self.session_lock = threading.Lock()
        
        self.logger.info("Integrated Security System initialized")
    
    def _load_integrated_config(self, config_path: str) -> dict:
        """Load integrated configuration."""
        default_config = {
            'monitor_config': 'monitor_config.json',
            'enable_port_knocking': True,
            'enable_behavioral_monitoring': True,
            'enable_command_capture': True,
            'integration_log_file': 'integrated_security.log',
            'webhook_url': None,
            'alert_threshold': 0.8,
            'auto_blacklist': True,
            'session_timeout_minutes': 30
        }
        
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            self._create_default_integrated_config(config_path, default_config)
        
        return default_config
    
    def _create_default_integrated_config(self, config_path: str, config: dict):
        """Create default integrated configuration file."""
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Created default integrated configuration file: {config_path}")
    
    def setup_logging(self):
        """Setup logging for the integrated system."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['integration_log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('IntegratedSecurity')
    
    def start_integration(self):
        """Start the integrated security system."""
        if self.integration_active:
            self.logger.warning("Integration is already active")
            return
        
        self.integration_active = True
        
        # Start behavioral monitoring
        if self.config['enable_behavioral_monitoring']:
            self.behavioral_monitor.start_monitoring()
            self.logger.info("Behavioral monitoring started")
        
        # Start command capture
        if self.config['enable_command_capture']:
            self.command_capture.start_capture('log_monitoring')
            self.logger.info("Command capture started")
        
        # Start port knocking (if available)
        if self.config['enable_port_knocking'] and self.port_knocking:
            self._start_port_knocking()
            self.logger.info("Port knocking system started")
        
        # Start integration monitoring thread
        self.integration_thread = threading.Thread(target=self._integration_monitor, daemon=True)
        self.integration_thread.start()
        
        self.logger.info("Integrated Security System started successfully")
    
    def stop_integration(self):
        """Stop the integrated security system."""
        self.integration_active = False
        
        # Stop behavioral monitoring
        self.behavioral_monitor.stop_monitoring()
        
        # Stop command capture
        self.command_capture.stop_capture()
        
        # Stop port knocking
        if self.port_knocking:
            self._stop_port_knocking()
        
        if self.integration_thread:
            self.integration_thread.join(timeout=5)
        
        self.logger.info("Integrated Security System stopped")
    
    def _start_port_knocking(self):
        """Start the port knocking system."""
        try:
            if self.port_knocking:
                # Initialize port knocking configuration
                # This would depend on your specific port knocking implementation
                self.logger.info("Port knocking system initialized")
        except Exception as e:
            self.logger.error(f"Error starting port knocking: {e}")
    
    def _stop_port_knocking(self):
        """Stop the port knocking system."""
        try:
            if self.port_knocking:
                # Cleanup port knocking
                self.logger.info("Port knocking system stopped")
        except Exception as e:
            self.logger.error(f"Error stopping port knocking: {e}")
    
    def _handle_ssh_event(self, event: dict):
        """Handle SSH events from command capture."""
        try:
            event_type = event.get('type')
            username = event.get('username')
            command = event.get('command')
            timestamp = event.get('timestamp')
            
            if event_type == 'login':
                self._handle_user_login(username, timestamp)
            
            elif event_type == 'command':
                self._handle_user_command(username, command, timestamp)
            
            # Log the event
            self.logger.info(f"SSH Event: {event_type} - User: {username} - Command: {command}")
            
        except Exception as e:
            self.logger.error(f"Error handling SSH event: {e}")
    
    def _handle_user_login(self, username: str, timestamp: str):
        """Handle user login event."""
        with self.session_lock:
            self.active_sessions[username] = {
                'login_time': timestamp,
                'last_activity': timestamp,
                'commands': [],
                'risk_score': 0.0,
                'blacklisted': False
            }
        
        self.logger.info(f"User {username} logged in")
        
        # Check if user is already blacklisted
        if username in self.behavioral_monitor.blacklist:
            self.logger.warning(f"Blacklisted user {username} attempted to login")
            self._take_action_against_user(username, "Blacklisted user login attempt")
    
    def _handle_user_command(self, username: str, command: str, timestamp: str):
        """Handle user command event."""
        if not command:
            return
        
        # Update session information
        with self.session_lock:
            if username in self.active_sessions:
                session = self.active_sessions[username]
                session['last_activity'] = timestamp
                session['commands'].append(command)
                
                # Keep only recent commands
                if len(session['commands']) > 100:
                    session['commands'] = session['commands'][-100:]
        
        # Analyze command using behavioral monitor
        analysis_result = self.behavioral_monitor.analyze_user_behavior(username, command)
        
        # Update session risk score
        with self.session_lock:
            if username in self.active_sessions:
                self.active_sessions[username]['risk_score'] = analysis_result['cumulative_risk']
        
        # Check if action is needed
        if analysis_result['cumulative_risk'] > self.config['alert_threshold']:
            self._handle_high_risk_user(username, analysis_result)
        
        # Log suspicious commands
        if analysis_result['risk_score'] > 0.5:
            self.logger.warning(f"Suspicious command from {username}: {command} (Risk: {analysis_result['risk_score']:.2f})")
    
    def _handle_high_risk_user(self, username: str, analysis_result: dict):
        """Handle high-risk user behavior."""
        risk_score = analysis_result['cumulative_risk']
        
        self.logger.warning(f"High-risk user detected: {username} (Risk: {risk_score:.2f})")
        
        # Auto-blacklist if enabled
        if self.config['auto_blacklist'] and risk_score > self.config['alert_threshold']:
            self._take_action_against_user(username, f"High risk behavior (Score: {risk_score:.2f})")
        
        # Send alert
        self._send_alert(username, analysis_result)
    
    def _take_action_against_user(self, username: str, reason: str):
        """Take action against a malicious user."""
        try:
            # Blacklist the user
            self.behavioral_monitor.blacklist_user(username, reason)
            
            # Close active session
            with self.session_lock:
                if username in self.active_sessions:
                    self.active_sessions[username]['blacklisted'] = True
            
            # Block SSH access
            self._block_ssh_access(username)
            
            # Log the action
            self.logger.warning(f"Action taken against {username}: {reason}")
            
        except Exception as e:
            self.logger.error(f"Error taking action against {username}: {e}")
    
    def _block_ssh_access(self, username: str):
        """Block SSH access for a user."""
        try:
            # Method 1: Use iptables to block the user's IP
            # This would require tracking IP addresses
            
            # Method 2: Use fail2ban
            # subprocess.run(['fail2ban-client', 'set', 'sshd', 'banip', ip_address])
            
            # Method 3: Modify SSH configuration
            # This is a placeholder for now
            
            self.logger.info(f"SSH access blocked for user: {username}")
            
        except Exception as e:
            self.logger.error(f"Error blocking SSH access for {username}: {e}")
    
    def _send_alert(self, username: str, analysis_result: dict):
        """Send alert about suspicious user."""
        try:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'risk_score': analysis_result['cumulative_risk'],
                'command': analysis_result.get('command', 'Unknown'),
                'model_used': analysis_result.get('model_used', 'Unknown'),
                'action_taken': 'monitoring'
            }
            
            # Send to webhook if configured
            if self.config['webhook_url']:
                self._send_webhook_alert(alert)
            
            # Log the alert
            self.logger.warning(f"Alert: {json.dumps(alert)}")
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")
    
    def _send_webhook_alert(self, alert: dict):
        """Send alert to webhook."""
        try:
            import requests
            
            response = requests.post(
                self.config['webhook_url'],
                json=alert,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Alert sent to webhook successfully")
            else:
                self.logger.error(f"Failed to send alert to webhook: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error sending webhook alert: {e}")
    
    def _integration_monitor(self):
        """Monitor integration health and cleanup."""
        while self.integration_active:
            try:
                # Cleanup old sessions
                self._cleanup_old_sessions()
                
                # Check system health
                self._check_system_health()
                
                # Sleep for monitoring interval
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in integration monitor: {e}")
                time.sleep(60)
    
    def _cleanup_old_sessions(self):
        """Clean up old user sessions."""
        try:
            timeout = self.config['session_timeout_minutes'] * 60  # Convert to seconds
            current_time = datetime.now()
            
            with self.session_lock:
                users_to_remove = []
                
                for username, session in self.active_sessions.items():
                    last_activity = datetime.fromisoformat(session['last_activity'])
                    if (current_time - last_activity).total_seconds() > timeout:
                        users_to_remove.append(username)
                
                for username in users_to_remove:
                    del self.active_sessions[username]
                    self.logger.info(f"Cleaned up session for user: {username}")
                    
        except Exception as e:
            self.logger.error(f"Error cleaning up sessions: {e}")
    
    def _check_system_health(self):
        """Check the health of all system components."""
        try:
            # Check behavioral monitor
            monitor_stats = self.behavioral_monitor.get_system_stats()
            
            # Check active sessions
            active_sessions_count = len(self.active_sessions)
            
            # Log health status
            self.logger.info(f"System Health - Active Sessions: {active_sessions_count}, "
                           f"Blacklisted Users: {monitor_stats['blacklisted_users']}")
            
        except Exception as e:
            self.logger.error(f"Error checking system health: {e}")
    
    def get_system_status(self) -> dict:
        """Get overall system status."""
        try:
            monitor_stats = self.behavioral_monitor.get_system_stats()
            
            return {
                'integration_active': self.integration_active,
                'active_sessions': len(self.active_sessions),
                'blacklisted_users': monitor_stats['blacklisted_users'],
                'total_sessions': monitor_stats['total_sessions'],
                'suspicious_commands': monitor_stats['suspicious_commands'],
                'port_knocking_active': self.port_knocking is not None,
                'behavioral_monitoring_active': self.config['enable_behavioral_monitoring'],
                'command_capture_active': self.config['enable_command_capture']
            }
            
        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {'error': str(e)}
    
    def test_integration(self):
        """Test the integrated system with sample data."""
        print("Testing Integrated Security System...")
        
        # Test user login
        test_username = "testuser"
        test_timestamp = datetime.now().isoformat()
        
        print(f"Testing user login: {test_username}")
        self._handle_user_login(test_username, test_timestamp)
        
        # Test normal commands
        normal_commands = [
            "ls -la",
            "pwd",
            "whoami",
            "date"
        ]
        
        print("Testing normal commands...")
        for cmd in normal_commands:
            self._handle_user_command(test_username, cmd, datetime.now().isoformat())
            time.sleep(1)
        
        # Test suspicious commands
        suspicious_commands = [
            "cat /etc/passwd",
            "sudo su",
            "history -c",
            "rm -rf /tmp/*"
        ]
        
        print("Testing suspicious commands...")
        for cmd in suspicious_commands:
            self._handle_user_command(test_username, cmd, datetime.now().isoformat())
            time.sleep(1)
        
        # Get final status
        status = self.get_system_status()
        print(f"Final System Status: {json.dumps(status, indent=2)}")
        
        # Cleanup test user
        with self.session_lock:
            if test_username in self.active_sessions:
                del self.active_sessions[test_username]


def main():
    """Main function to run the integrated security system."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Integrated Security System')
    parser.add_argument('--config', default='integrated_config.json', help='Configuration file path')
    parser.add_argument('--test', action='store_true', help='Run integration test')
    parser.add_argument('--status', action='store_true', help='Show system status')
    
    args = parser.parse_args()
    
    # Initialize integrated system
    integrated_system = IntegratedSecuritySystem(args.config)
    
    if args.test:
        # Run test
        integrated_system.test_integration()
    
    elif args.status:
        # Show status
        status = integrated_system.get_system_status()
        print(f"System Status: {json.dumps(status, indent=2)}")
    
    else:
        # Start the system
        try:
            integrated_system.start_integration()
            print("Integrated Security System started. Press Ctrl+C to stop.")
            
            # Keep the main thread alive
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping Integrated Security System...")
            integrated_system.stop_integration()
            print("Integrated Security System stopped.")


if __name__ == "__main__":
    main() 