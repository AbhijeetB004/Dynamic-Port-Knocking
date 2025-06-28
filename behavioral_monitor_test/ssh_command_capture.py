#!/usr/bin/env python3
"""
SSH Command Capture Module
Captures SSH commands in real-time for behavioral analysis

This module provides multiple methods to capture SSH commands:
1. Using auditd (recommended)
2. Using strace
3. Using ptrace
4. Using system call monitoring
"""

import os
import sys
import time
import json
import logging
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable
import re

class SSHCommandCapture:
    """Captures SSH commands in real-time for behavioral monitoring."""
    
    def __init__(self, callback: Optional[Callable] = None):
        """Initialize SSH command capture."""
        self.callback = callback
        self.capture_active = False
        self.capture_thread = None
        self.logger = logging.getLogger('SSHCommandCapture')
        
        # Command patterns to look for
        self.command_patterns = [
            r'execve\("([^"]+)"',
            r'write\([0-9]+, "([^"]+)"',
            r'read\([0-9]+, "([^"]+)"'
        ]
        
        # SSH-related processes
        self.ssh_processes = set()
        
    def setup_auditd(self) -> bool:
        """Setup auditd for command capture."""
        try:
            # Check if auditd is installed
            result = subprocess.run(['which', 'auditd'], capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error("auditd not found. Please install auditd.")
                return False
            
            # Create audit rules for SSH command capture
            audit_rules = [
                # Monitor execve syscalls for SSH processes
                '-a always,exit -F arch=b64 -S execve -F path=/usr/bin/ssh -k ssh_commands',
                '-a always,exit -F arch=b64 -S execve -F path=/usr/bin/bash -k ssh_commands',
                '-a always,exit -F arch=b64 -S execve -F path=/bin/bash -k ssh_commands',
                '-a always,exit -F arch=b64 -S execve -F path=/bin/sh -k ssh_commands',
                
                # Monitor file writes for command history
                '-w /home -p wa -k ssh_commands',
                '-w /root -p wa -k ssh_commands',
                
                # Monitor specific files
                '-w /var/log/auth.log -p wa -k ssh_commands',
                '-w /var/log/secure -p wa -k ssh_commands'
            ]
            
            # Add rules to auditd
            for rule in audit_rules:
                subprocess.run(['auditctl', '-w'] + rule.split()[1:], check=True)
            
            self.logger.info("auditd rules configured successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error setting up auditd: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error setting up auditd: {e}")
            return False
    
    def start_capture(self, method: str = 'auditd'):
        """Start command capture using specified method."""
        if self.capture_active:
            self.logger.warning("Command capture is already active")
            return
        
        self.capture_active = True
        
        if method == 'auditd':
            if self.setup_auditd():
                self.capture_thread = threading.Thread(target=self._capture_auditd, daemon=True)
                self.capture_thread.start()
                self.logger.info("Started auditd-based command capture")
            else:
                self.logger.error("Failed to setup auditd, falling back to log monitoring")
                self._start_log_monitoring()
        
        elif method == 'strace':
            self.capture_thread = threading.Thread(target=self._capture_strace, daemon=True)
            self.capture_thread.start()
            self.logger.info("Started strace-based command capture")
        
        elif method == 'log_monitoring':
            self._start_log_monitoring()
        
        else:
            self.logger.error(f"Unknown capture method: {method}")
            self.capture_active = False
    
    def stop_capture(self):
        """Stop command capture."""
        self.capture_active = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        self.logger.info("Command capture stopped")
    
    def _capture_auditd(self):
        """Capture commands using auditd."""
        try:
            # Monitor audit log for SSH commands
            process = subprocess.Popen(
                ['ausearch', '-k', 'ssh_commands', '-ts', 'now'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in process.stdout:
                if not self.capture_active:
                    break
                
                self._process_audit_line(line)
                
        except Exception as e:
            self.logger.error(f"Error in auditd capture: {e}")
        finally:
            if process:
                process.terminate()
    
    def _process_audit_line(self, line: str):
        """Process a single audit log line."""
        try:
            # Parse audit log line
            if 'type=EXECVE' in line:
                # Extract command from execve event
                match = re.search(r'arg0="([^"]+)"', line)
                if match:
                    command = match.group(1)
                    self._extract_user_and_command(line, command)
            
            elif 'type=PATH' in line and 'name=' in line:
                # Extract file operations
                match = re.search(r'name="([^"]+)"', line)
                if match:
                    filename = match.group(1)
                    if self._is_suspicious_file(filename):
                        self._extract_user_and_command(line, f"file_access:{filename}")
                        
        except Exception as e:
            self.logger.error(f"Error processing audit line: {e}")
    
    def _capture_strace(self):
        """Capture commands using strace (experimental)."""
        try:
            # Find SSH processes
            ssh_pids = self._get_ssh_processes()
            
            for pid in ssh_pids:
                self._strace_process(pid)
                
        except Exception as e:
            self.logger.error(f"Error in strace capture: {e}")
    
    def _get_ssh_processes(self) -> List[int]:
        """Get list of SSH process PIDs."""
        try:
            result = subprocess.run(['pgrep', 'ssh'], capture_output=True, text=True)
            if result.returncode == 0:
                return [int(pid) for pid in result.stdout.strip().split('\n') if pid]
        except Exception as e:
            self.logger.error(f"Error getting SSH processes: {e}")
        return []
    
    def _strace_process(self, pid: int):
        """Attach strace to a process."""
        try:
            process = subprocess.Popen(
                ['strace', '-p', str(pid), '-e', 'trace=execve,write'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in process.stderr:
                if not self.capture_active:
                    break
                
                self._process_strace_line(line, pid)
                
        except Exception as e:
            self.logger.error(f"Error strace-ing process {pid}: {e}")
    
    def _process_strace_line(self, line: str, pid: int):
        """Process a single strace line."""
        try:
            if 'execve(' in line:
                # Extract command from execve
                match = re.search(r'execve\("([^"]+)"', line)
                if match:
                    command = match.group(1)
                    self._handle_command(pid, command)
            
            elif 'write(' in line and 'bash' in line:
                # Extract command from write to bash
                match = re.search(r'write\([0-9]+, "([^"]+)"', line)
                if match:
                    command = match.group(1)
                    if len(command.strip()) > 0:
                        self._handle_command(pid, command.strip())
                        
        except Exception as e:
            self.logger.error(f"Error processing strace line: {e}")
    
    def _start_log_monitoring(self):
        """Start monitoring SSH logs for commands."""
        log_files = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/sshd.log'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                thread = threading.Thread(
                    target=self._monitor_log_file,
                    args=(log_file,),
                    daemon=True
                )
                thread.start()
                self.logger.info(f"Started monitoring log file: {log_file}")
    
    def _monitor_log_file(self, log_file: str):
        """Monitor a specific log file."""
        try:
            process = subprocess.Popen(
                ['tail', '-f', log_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in process.stdout:
                if not self.capture_active:
                    break
                
                self._process_log_line(line, log_file)
                
        except Exception as e:
            self.logger.error(f"Error monitoring log file {log_file}: {e}")
        finally:
            if process:
                process.terminate()
    
    def _process_log_line(self, line: str, log_file: str):
        """Process a single log line."""
        try:
            # Look for command execution patterns
            if any(pattern in line for pattern in ['Accepted password', 'Accepted publickey', 'session opened']):
                # Extract username from login events
                username = self._extract_username_from_log(line)
                if username:
                    self._handle_user_login(username)
            
            # Look for command execution (this is limited in auth.log)
            # You might need to use other methods for actual command capture
            
        except Exception as e:
            self.logger.error(f"Error processing log line: {e}")
    
    def _extract_username_from_log(self, line: str) -> Optional[str]:
        """Extract username from log line."""
        try:
            # Common patterns for username extraction
            patterns = [
                r'Accepted password for ([^\s]+)',
                r'Accepted publickey for ([^\s]+)',
                r'session opened for user ([^\s]+)',
                r'User ([^\s]+) logged in'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting username: {e}")
            return None
    
    def _extract_user_and_command(self, line: str, command: str):
        """Extract user and command from audit/log line."""
        try:
            # Extract user from audit line
            user_match = re.search(r'auid=([^\s]+)', line)
            if user_match:
                auid = user_match.group(1)
                username = self._get_username_from_auid(auid)
                if username:
                    self._handle_command(username, command)
            
        except Exception as e:
            self.logger.error(f"Error extracting user and command: {e}")
    
    def _get_username_from_auid(self, auid: str) -> Optional[str]:
        """Get username from audit user ID."""
        try:
            if auid == '4294967295' or auid == '-1':
                return 'unknown'
            
            # Try to get username from /etc/passwd
            result = subprocess.run(['id', '-un', auid], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting username from auid: {e}")
            return None
    
    def _is_suspicious_file(self, filename: str) -> bool:
        """Check if a file access is suspicious."""
        suspicious_patterns = [
            '/etc/passwd',
            '/etc/shadow',
            '/proc/',
            '/sys/',
            '/root/',
            '.bash_history',
            '.ssh/'
        ]
        
        return any(pattern in filename for pattern in suspicious_patterns)
    
    def _handle_user_login(self, username: str):
        """Handle user login event."""
        if self.callback:
            self.callback({
                'type': 'login',
                'username': username,
                'timestamp': datetime.now().isoformat(),
                'command': None
            })
    
    def _handle_command(self, user: str, command: str):
        """Handle command execution event."""
        if self.callback:
            self.callback({
                'type': 'command',
                'username': user,
                'timestamp': datetime.now().isoformat(),
                'command': command
            })


def test_command_capture():
    """Test the command capture functionality."""
    def callback(event):
        print(f"Captured event: {json.dumps(event, indent=2)}")
    
    capture = SSHCommandCapture(callback)
    
    print("Starting command capture test...")
    capture.start_capture('log_monitoring')
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping command capture...")
        capture.stop_capture()


if __name__ == "__main__":
    test_command_capture() 