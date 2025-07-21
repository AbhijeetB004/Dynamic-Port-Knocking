#!/usr/bin/env python3
"""
Response Engine
Handles automated responses to detected threats including blacklisting, warnings, and session termination.
"""

import asyncio
import json
import logging
import os
import psutil
import subprocess
import signal
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from telegram_alert import TelegramAlert

class ResponseEngine:
    """Handles automated responses to security threats"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Blacklist management
        self.blacklist_file = Path(config.response.blacklist_file)
        self.blacklisted_ips = set()
        self.blacklist_lock = threading.Lock()
        
        # Response tracking
        self.response_history = []
        self.active_warnings = {}
        
        # Integration with port knocking
        self.port_knocking_blacklist = Path(config.response.port_knocking_blacklist_file)
        
        # Email notifications
        self.smtp_config = config.response.smtp if hasattr(config.response, 'smtp') else None
        
        # Telegram alerts
        self.telegram_alert = TelegramAlert(config)
        
        self.logger.info("Response Engine initialized")
    
    async def initialize(self):
        """Initialize response engine"""
        try:
            # Load existing blacklist
            await self._load_blacklist()
            
            # Initialize response mechanisms
            await self._initialize_response_mechanisms()
            
            # Start cleanup task
            asyncio.create_task(self._cleanup_expired_entries())
            
            self.logger.info("Response engine initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing response engine: {e}")
            raise
    
    async def _load_blacklist(self):
        """Load existing blacklist from file"""
        try:
            if self.blacklist_file.exists():
                with open(self.blacklist_file, 'r') as f:
                    content = f.read().strip()
                    if content:  # Only try to parse if file is not empty
                        data = json.loads(content)
                        
                        with self.blacklist_lock:
                            for entry in data.get('blacklist', []):
                                if not self._is_expired(entry):
                                    self.blacklisted_ips.add(entry['ip'])
                        
                        self.logger.info(f"Loaded {len(self.blacklisted_ips)} blacklisted IPs")
                    else:
                        self.logger.info("Blacklist file is empty, starting with empty blacklist")
            else:
                self.logger.info("Blacklist file does not exist, starting with empty blacklist")
            
        except Exception as e:
            self.logger.error(f"Error loading blacklist: {e}")
            # Continue with empty blacklist
    
    async def _initialize_response_mechanisms(self):
        """Initialize response mechanisms"""
        try:
            # Create blacklist file if it doesn't exist
            if not self.blacklist_file.exists():
                self.blacklist_file.parent.mkdir(parents=True, exist_ok=True)
                await self._save_blacklist()
            
            # Create port knocking blacklist symlink/copy
            if not self.port_knocking_blacklist.exists():
                self.port_knocking_blacklist.parent.mkdir(parents=True, exist_ok=True)
                # Create a copy for port knocking system
                await self._sync_port_knocking_blacklist()
            
            self.logger.info("Response mechanisms initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing response mechanisms: {e}")
            raise
    
    async def blacklist_ip(self, ip_address: str, reason: str, session_info: Dict, analysis_result: Dict):
        """Blacklist an IP address"""
        try:
            with self.blacklist_lock:
                if ip_address not in self.blacklisted_ips:
                    self.blacklisted_ips.add(ip_address)
                    
                    # Create blacklist entry
                    entry = {
                        'ip': ip_address,
                        'reason': reason,
                        'timestamp': datetime.now().isoformat(),
                        'expires': (datetime.now() + timedelta(seconds=self.config.response.blacklist_duration)).isoformat(),
                        'session_info': session_info,
                        'analysis_result': analysis_result
                    }
                    
                    # Save to file
                    await self._add_blacklist_entry(entry)
                    
                    # Sync with port knocking system
                    await self._sync_port_knocking_blacklist()
                    
                    # Log security event
                    self.logger.critical(f"IP BLACKLISTED: {ip_address} - {reason}")
                    
                    # Send notifications
                    await self._send_blacklist_notification(entry)
                    
                    # Record response
                    self._record_response('blacklist', ip_address, reason, analysis_result)
                    
                    # Send Telegram alert
                    await self.telegram_alert.send_blacklist_alert(session_info, 
                                                                  analysis_result.get('risk_score', 0.0), 
                                                                  analysis_result)
                    
                    return True
                else:
                    self.logger.info(f"IP {ip_address} already blacklisted")
                    return False
        
        except Exception as e:
            self.logger.error(f"Error blacklisting IP {ip_address}: {e}")
            return False
    
    async def _add_blacklist_entry(self, entry: Dict):
        """Add entry to blacklist file"""
        try:
            # Load existing data
            data = {'blacklist': []}
            if self.blacklist_file.exists():
                with open(self.blacklist_file, 'r') as f:
                    data = json.load(f)
            
            # Add new entry
            data['blacklist'].append(entry)
            
            # Save updated data
            with open(self.blacklist_file, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error adding blacklist entry: {e}")
            raise
    
    async def _sync_port_knocking_blacklist(self):
        """Sync blacklist with port knocking system"""
        try:
            # Create simple IP list for port knocking system
            blacklist_data = {
                'blacklisted_ips': list(self.blacklisted_ips),
                'last_updated': datetime.now().isoformat()
            }
            
            # Ensure directory exists
            self.port_knocking_blacklist.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.port_knocking_blacklist, 'w') as f:
                json.dump(blacklist_data, f, indent=2)
            
            self.logger.debug("Synced blacklist with port knocking system")
            
        except Exception as e:
            self.logger.error(f"Error syncing blacklist: {e}")
            # Non-critical error, continue
    
    async def warn_user(self, session_id: str, risk_score: float, predictions: Dict, warning_count: int):
        """Issue warning to user"""
        try:
            # Create warning message
            warning_msg = self._create_warning_message(risk_score, predictions, warning_count)
            
            # Send warning to user session
            await self._send_session_warning(session_id, warning_msg)
            
            # Log warning
            self.logger.warning(f"WARNING SENT to session {session_id}: {warning_msg}")
            
            # Track warning
            self.active_warnings[session_id] = {
                'count': warning_count,
                'last_warning': datetime.now(),
                'risk_score': risk_score
            }
            
            # Send notification
            await self._send_warning_notification(session_id, risk_score, predictions)
            
            # Record response
            self._record_response('warning', session_id, warning_msg, predictions)
            
            # Send Telegram alert
            await self.telegram_alert.send_warning_alert(
                {'session_id': session_id}, 
                risk_score, 
                {'predictions': predictions}, 
                warning_count
            )
            
        except Exception as e:
            self.logger.error(f"Error warning user: {e}")
    
    def _create_warning_message(self, risk_score: float, predictions: Dict, warning_count: int) -> str:
        """Create warning message for user"""
        top_threats = sorted(predictions.items(), key=lambda x: x[1], reverse=True)[:3]
        threat_text = ", ".join([f"{threat}: {score:.2f}" for threat, score in top_threats])
        
        warning_msg = f"""
        ⚠️  SECURITY WARNING #{warning_count} ⚠️
        
        Suspicious activity detected in your session.
        Risk Score: {risk_score:.3f}
        Top Threats: {threat_text}
        
        Please review your recent commands.
        Further suspicious activity may result in session termination.
        
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        return warning_msg
    
    async def _send_session_warning(self, session_id: str, warning_msg: str):
        """Send warning message to user session"""
        try:
            # Try to send warning via wall command (broadcasts to all terminals)
            wall_msg = f"Security Warning for session {session_id}:\n{warning_msg}"
            
            # Write warning to all terminals of the user
            result = subprocess.run(
                ['wall'],
                input=wall_msg,
                text=True,
                capture_output=True
            )
            
            if result.returncode == 0:
                self.logger.debug(f"Warning sent via wall command")
            else:
                self.logger.debug(f"Wall command failed: {result.stderr}")
                
                # Alternative: try to write to specific terminal
                await self._send_terminal_warning(session_id, warning_msg)
        
        except Exception as e:
            self.logger.error(f"Error sending session warning: {e}")
    
    async def _send_terminal_warning(self, session_id: str, warning_msg: str):
        """Send warning to specific terminal"""
        try:
            # Find terminal associated with session
            # This is a simplified approach - in production, you'd need better session tracking
            
            # Try to find SSH processes and their terminals
            for proc in psutil.process_iter(['pid', 'name', 'terminal']):
                try:
                    if proc.info['name'] == 'sshd' and proc.info['terminal']:
                        terminal = proc.info['terminal']
                        
                        # Write warning to terminal
                        with open(f"/dev/{terminal}", 'w') as term:
                            term.write(f"\n{warning_msg}\n")
                        
                        self.logger.debug(f"Warning sent to terminal {terminal}")
                        break
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
                    continue
        
        except Exception as e:
            self.logger.error(f"Error sending terminal warning: {e}")
    
    async def terminate_session(self, session_id: str):
        """Terminate an SSH session"""
        try:
            # Extract PID from session_id (format: ip_pid)
            if '_' in session_id:
                parts = session_id.split('_')
                if len(parts) >= 2:
                    try:
                        pid = int(parts[-1])
                        
                        # Find and terminate the process
                        if psutil.pid_exists(pid):
                            proc = psutil.Process(pid)
                            if proc.name() in ['sshd', 'ssh']:
                                proc.terminate()
                                
                                # Wait for graceful termination
                                await asyncio.sleep(2)
                                
                                # Force kill if still running
                                if proc.is_running():
                                    proc.kill()
                                
                                self.logger.info(f"Terminated session {session_id} (PID: {pid})")
                                return True
                        
                    except (ValueError, psutil.NoSuchProcess):
                        pass
            
            # Alternative: try to find SSH processes by session info
            await self._terminate_ssh_processes_by_session(session_id)
            
        except Exception as e:
            self.logger.error(f"Error terminating session {session_id}: {e}")
            return False
    
    async def _terminate_ssh_processes_by_session(self, session_id: str):
        """Terminate SSH processes by session ID"""
        try:
            # Extract IP from session_id
            ip_address = session_id.split('_')[0]
            
            # Find SSH processes connected to this IP
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] == 'sshd':
                        try:
                            connections = proc.net_connections()
                            for conn in connections:
                                if (conn.status == 'ESTABLISHED' and 
                                    conn.raddr and conn.raddr.ip == ip_address):
                                    
                                    proc.terminate()
                                    self.logger.info(f"Terminated SSH process {proc.info['pid']} for IP {ip_address}")
                                
                                # Send Telegram alert for session termination
                                await self.telegram_alert.send_session_terminated_alert(
                                    {'ip_address': ip_address, 'session_id': session_id}, 
                                    0.0, 
                                    {'predictions': {}, 'dominant_category': 'Session Termination'}
                                )
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            continue
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            self.logger.error(f"Error terminating SSH processes: {e}")
    
    async def _send_blacklist_notification(self, entry: Dict):
        """Send notification about blacklisted IP"""
        try:
            if self.smtp_config:
                subject = f"Security Alert: IP {entry['ip']} Blacklisted"
                body = f"""
                Security Alert: IP Blacklisted
                
                IP Address: {entry['ip']}
                Reason: {entry['reason']}
                Timestamp: {entry['timestamp']}
                
                Session Information:
                User: {entry['session_info'].get('user', 'unknown')}
                Session ID: {entry['session_info'].get('session_id', 'unknown')}
                
                Analysis Results:
                {json.dumps(entry['analysis_result'], indent=2)}
                
                The IP has been automatically blacklisted for {self.config.response.blacklist_duration} seconds.
                """
                
                await self._send_email(subject, body)
        
        except Exception as e:
            self.logger.error(f"Error sending blacklist notification: {e}")
    
    async def _send_warning_notification(self, session_id: str, risk_score: float, predictions: Dict):
        """Send notification about warning issued"""
        try:
            if self.smtp_config:
                subject = f"Security Warning: Suspicious Activity Detected"
                body = f"""
                Security Warning: Suspicious Activity Detected
                
                Session ID: {session_id}
                Risk Score: {risk_score:.3f}
                
                Threat Analysis:
                {json.dumps(predictions, indent=2)}
                
                Timestamp: {datetime.now().isoformat()}
                
                A warning has been issued to the user.
                """
                
                await self._send_email(subject, body)
        
        except Exception as e:
            self.logger.error(f"Error sending warning notification: {e}")
    
    async def _send_email(self, subject: str, body: str):
        """Send email notification"""
        try:
            if not self.smtp_config:
                return
            
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config['from']
            msg['To'] = self.smtp_config['to']
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                if self.smtp_config.get('use_tls', False):
                    server.starttls()
                
                if self.smtp_config.get('username') and self.smtp_config.get('password'):
                    server.login(self.smtp_config['username'], self.smtp_config['password'])
                
                server.send_message(msg)
            
            self.logger.debug("Email notification sent")
        
        except Exception as e:
            self.logger.error(f"Error sending email: {e}")
    
    def _record_response(self, response_type: str, target: str, reason: str, analysis_result: Dict):
        """Record response in history"""
        try:
            response_record = {
                'timestamp': datetime.now().isoformat(),
                'type': response_type,
                'target': target,
                'reason': reason,
                'analysis_result': analysis_result
            }
            
            self.response_history.append(response_record)
            
            # Keep only recent history
            if len(self.response_history) > self.config.response.max_history:
                self.response_history = self.response_history[-self.config.response.max_history:]
        
        except Exception as e:
            self.logger.error(f"Error recording response: {e}")
    
    def _is_expired(self, entry: Dict) -> bool:
        """Check if blacklist entry is expired"""
        try:
            expires = datetime.fromisoformat(entry.get('expires', ''))
            return datetime.now() > expires
        except:
            return False
    
    async def _cleanup_expired_entries(self):
        """Clean up expired blacklist entries"""
        while True:
            try:
                # Sleep for a configured interval (default: 60 seconds)
                await asyncio.sleep(getattr(self.config.response, 'cleanup_interval', 60))

                # Load current blacklist
                if self.blacklist_file.exists():
                    with open(self.blacklist_file, 'r') as f:
                        content = f.read().strip()
                        if content:
                            data = json.loads(content)
                        else:
                            data = {'blacklist': []}
                else:
                    data = {'blacklist': []}

                # Remove expired entries
                new_blacklist = []
                removed_ips = set()
                for entry in data.get('blacklist', []):
                    if not self._is_expired(entry):
                        new_blacklist.append(entry)
                    else:
                        removed_ips.add(entry['ip'])

                # Update file if any entries were removed
                if len(new_blacklist) != len(data.get('blacklist', [])):
                    with open(self.blacklist_file, 'w') as f:
                        json.dump({'blacklist': new_blacklist}, f, indent=2)

                # Update in-memory blacklist
                with self.blacklist_lock:
                    self.blacklisted_ips -= removed_ips

                # Sync with port knocking system
                await self._sync_port_knocking_blacklist()

                if removed_ips:
                    self.logger.info(f"Cleaned up expired blacklist entries: {removed_ips}")

            except Exception as e:
                self.logger.error(f"Error during blacklist cleanup: {e}")
    
    async def _save_blacklist(self):
        """Save the current blacklist to file."""
        try:
            data = {'blacklist': []}
            if self.blacklist_file.exists():
                with open(self.blacklist_file, 'r') as f:
                    data = json.load(f)
            # Update with current in-memory blacklist
            # Optionally, you can keep only non-expired entries
            with self.blacklist_lock:
                data['blacklist'] = [
                    entry for entry in data.get('blacklist', [])
                    if not self._is_expired(entry)
                ]
                # Add any new IPs not already in the file
                existing_ips = {entry['ip'] for entry in data['blacklist']}
                for ip in self.blacklisted_ips:
                    if ip not in existing_ips:
                        data['blacklist'].append({
                            'ip': ip,
                            'reason': 'manual or unknown',
                            'timestamp': datetime.now().isoformat(),
                            'expires': (datetime.now() + timedelta(seconds=self.config.response.blacklist_duration)).isoformat(),
                            'session_info': {},
                            'analysis_result': {}
                        })
            with open(self.blacklist_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving blacklist: {e}")
    
    async def stop(self):
        """Stop the response engine (placeholder for cleanup if needed)."""
        self.logger.info("Response engine stopped")