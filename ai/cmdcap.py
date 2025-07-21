#!/usr/bin/env python3
"""
SSH Command Capture Module
Captures SSH commands using shell hooks and process monitoring.
"""

import asyncio
import json
import logging
import os
import psutil
import re
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator
import tempfile
import threading
from dataclasses import dataclass

@dataclass
class CommandData:
    """Data structure for captured command"""
    session_id: str
    command: str
    user: str
    ip_address: str
    timestamp: datetime
    pid: int
    ppid: int

class SSHCommandCapture:
    """Captures SSH commands using multiple methods"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Command queue
        self.command_queue = asyncio.Queue()
        
        # Shell hook files
        self.hook_dir = Path(config.capture.hook_directory)
        self.hook_dir.mkdir(parents=True, exist_ok=True)
        
        # Process monitoring
        self.monitoring_active = False
        self.known_ssh_processes = set()
        
        # SSH session tracking
        self.ssh_sessions = {}
        self.session_lock = threading.Lock()
        
        self.logger.info("SSH Command Capture initialized")
    
    async def initialize(self):
        """Initialize command capture system"""
        try:
            # Setup shell hooks
            await self._setup_shell_hooks()
            
            # Start process monitoring
            await self._start_process_monitoring()
            
            # Start command file monitoring
            await self._start_file_monitoring()
            
            self.logger.info("Command capture system initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing command capture: {e}")
            raise
    
    async def _setup_shell_hooks(self):
        """Setup shell hooks for command capture"""
        try:
            # Create bash hook script
            bash_hook = self.hook_dir / "bash_hook.sh"
            bash_hook_content = f"""#!/bin/bash
# SSH Command Capture Hook for Bash

# Function to log commands
log_command() {{
    local cmd="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
    local session_id="${{SSH_CLIENT}}_${{PPID}}"
    local user="${{USER}}"
    local ip_address=$(echo "${{SSH_CLIENT}}" | cut -d' ' -f1)
    local pid=$$
    local ppid=${{PPID}}
    
    # Skip empty commands and certain system commands
    if [[ -z "$cmd" || "$cmd" =~ ^(exit|logout|history|clear|ls|pwd|cd|echo|cat|less|more|tail|head|grep|find|which|whereis|type|alias|unalias|help|man|info)$ ]]; then
        return
    fi
    
    # Create JSON log entry
    local log_entry=$(cat <<EOF
{{
    "session_id": "$session_id",
    "command": "$cmd",
    "user": "$user",
    "ip_address": "$ip_address",
    "timestamp": "$timestamp",
    "pid": $pid,
    "ppid": $ppid
}}
EOF
)
    
    # Write to command log file
    echo "$log_entry" >> "{self.hook_dir}/commands.log"
}}

# Hook into bash prompt command
if [[ -n "${{SSH_CLIENT}}" ]]; then
    # Function to capture command before execution
    capture_command() {{
        local cmd=$(history 1 | sed 's/^[ ]*[0-9]*[ ]*//')
        if [[ -n "$cmd" && "$cmd" != "$LAST_COMMAND" ]]; then
            log_command "$cmd"
            LAST_COMMAND="$cmd"
        fi
    }}
    
    # Set up prompt command
    if [[ -z "${{PROMPT_COMMAND}}" ]]; then
        PROMPT_COMMAND="capture_command"
    else
        PROMPT_COMMAND="capture_command; ${{PROMPT_COMMAND}}"
    fi
fi
"""
            
            bash_hook.write_text(bash_hook_content)
            bash_hook.chmod(0o755)
            
            # Create zsh hook script
            zsh_hook = self.hook_dir / "zsh_hook.sh"
            zsh_hook_content = f"""#!/bin/zsh
# SSH Command Capture Hook for Zsh

# Function to log commands
log_command() {{
    local cmd="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
    local session_id="${{SSH_CLIENT}}_${{PPID}}"
    local user="${{USER}}"
    local ip_address=$(echo "${{SSH_CLIENT}}" | cut -d' ' -f1)
    local pid=$$
    local ppid=${{PPID}}
    
    # Skip empty commands and certain system commands
    if [[ -z "$cmd" || "$cmd" =~ "^(exit|logout|history|clear|ls|pwd|cd|echo|cat|less|more|tail|head|grep|find|which|whereis|type|alias|unalias|help|man|info)$" ]]; then
        return
    fi
    
    # Create JSON log entry
    local log_entry=$(cat <<EOF
{{
    "session_id": "$session_id",
    "command": "$cmd",
    "user": "$user",
    "ip_address": "$ip_address",
    "timestamp": "$timestamp",
    "pid": $pid,
    "ppid": $ppid
}}
EOF
)
    
    # Write to command log file
    echo "$log_entry" >> "{self.hook_dir}/commands.log"
}}

# Hook into zsh preexec
if [[ -n "${{SSH_CLIENT}}" ]]; then
    preexec() {{
        log_command "$1"
    }}
fi
"""
            
            zsh_hook.write_text(zsh_hook_content)
            zsh_hook.chmod(0o755)
            
            # Install hooks in system profiles
            await self._install_system_hooks()
            
            self.logger.info("Shell hooks created successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up shell hooks: {e}")
            raise
    
    async def _install_system_hooks(self):
        """Install hooks in system shell profiles"""
        try:
            # Profile configurations
            hook_source_line = f"source {self.hook_dir}/bash_hook.sh"
            zsh_hook_source_line = f"source {self.hook_dir}/zsh_hook.sh"
            
            # System-wide bash profile (requires sudo)
            bash_profiles = [
                Path("/etc/bash.bashrc"),
                Path("/etc/bashrc"),
                Path("/etc/profile")
            ]
            
            for profile in bash_profiles:
                if profile.exists():
                    content = profile.read_text()
                    if hook_source_line not in content:
                        # Backup original
                        backup_path = profile.with_suffix('.backup')
                        if not backup_path.exists():
                            profile.rename(backup_path)
                            backup_path.rename(profile)
                        
                        # Add hook
                        with profile.open('a') as f:
                            f.write(f"\n# SSH Command Capture Hook\n{hook_source_line}\n")
                        
                        self.logger.info(f"Installed bash hook in {profile}")
                        break
            
            # System-wide zsh profile (requires sudo)
            zsh_profiles = [
                Path("/etc/zsh/zshrc"),
                Path("/etc/zshrc")
            ]
            
            for profile in zsh_profiles:
                if profile.exists():
                    content = profile.read_text()
                    if zsh_hook_source_line not in content:
                        # Backup original
                        backup_path = profile.with_suffix('.backup')
                        if not backup_path.exists():
                            profile.rename(backup_path)
                            backup_path.rename(profile)
                        
                        # Add hook
                        with profile.open('a') as f:
                            f.write(f"\n# SSH Command Capture Hook\n{zsh_hook_source_line}\n")
                        
                        self.logger.info(f"Installed zsh hook in {profile}")
                        break
            
        except Exception as e:
            self.logger.error(f"Error installing system hooks: {e}")
            # Non-critical error, continue
    
    async def _start_process_monitoring(self):
        """Start monitoring SSH processes"""
        try:
            self.monitoring_active = True
            
            # Start process monitoring task
            asyncio.create_task(self._monitor_ssh_processes())
            
            self.logger.info("Process monitoring started")
            
        except Exception as e:
            self.logger.error(f"Error starting process monitoring: {e}")
            raise
    
    async def _monitor_ssh_processes(self):
        """Monitor SSH processes for new sessions"""
        while self.monitoring_active:
            try:
                current_ssh_processes = set()
                
                # Find all SSH processes
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        if proc.info['name'] in ['sshd', 'ssh']:
                            # Get SSH connection info using the process object
                            try:
                                connections = proc.net_connections()
                                for conn in connections:
                                    if conn.status == 'ESTABLISHED':
                                        session_info = {
                                            'pid': proc.info['pid'],
                                            'user': proc.info['username'],
                                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                                            'session_id': f"{conn.raddr.ip}_{proc.info['pid']}"
                                        }
                                        
                                        current_ssh_processes.add(session_info['session_id'])
                                        
                                        # Track new sessions
                                        if session_info['session_id'] not in self.ssh_sessions:
                                            with self.session_lock:
                                                self.ssh_sessions[session_info['session_id']] = session_info
                                            
                                            self.logger.info(f"New SSH session detected: {session_info['session_id']}")
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                # Process may have ended or we don't have permission
                                continue
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Remove ended sessions
                with self.session_lock:
                    ended_sessions = set(self.ssh_sessions.keys()) - current_ssh_processes
                    for session_id in ended_sessions:
                        del self.ssh_sessions[session_id]
                        self.logger.info(f"SSH session ended: {session_id}")
                
                # Sleep before next check
                await asyncio.sleep(self.config.capture.process_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in process monitoring: {e}")
                await asyncio.sleep(5)
    
    async def _start_file_monitoring(self):
        """Start monitoring command log files"""
        try:
            # Initialize command log file
            command_log_file = self.hook_dir / "commands.log"
            command_log_file.touch()
            
            # Start file monitoring task
            asyncio.create_task(self._monitor_command_file(command_log_file))
            
            self.logger.info("File monitoring started")
            
        except Exception as e:
            self.logger.error(f"Error starting file monitoring: {e}")
            raise
    
    async def _monitor_command_file(self, log_file: Path):
        """Monitor command log file for new entries"""
        last_position = 0
        
        while self.monitoring_active:
            try:
                if log_file.exists():
                    with open(log_file, 'r') as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        last_position = f.tell()
                        
                        # Collect complete JSON objects
                        json_buffer = ""
                        for line in new_lines:
                            line = line.strip()
                            self.logger.info(f"Read line: {line}")
                            if line:
                                json_buffer += line
                                if line.endswith("}"):  # End of JSON object
                                    try:
                                        command_data = json.loads(json_buffer)
                                        await self.command_queue.put(command_data)
                                        self.logger.info(f"Queued command: {command_data}")
                                    except json.JSONDecodeError:
                                        self.logger.debug(f"Invalid JSON in log: {json_buffer}")
                                    json_buffer = ""  # Reset buffer
                
                await asyncio.sleep(self.config.capture.file_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error monitoring command file: {e}")
                await asyncio.sleep(5)
    
    async def get_commands(self, timeout: float = 1.0) -> List[Dict]:
        """Get captured commands from the queue"""
        commands = []
        
        try:
            # Get all available commands within timeout
            end_time = asyncio.get_event_loop().time() + timeout
            
            while asyncio.get_event_loop().time() < end_time:
                try:
                    remaining_time = end_time - asyncio.get_event_loop().time()
                    if remaining_time <= 0:
                        break
                    
                    command_data = await asyncio.wait_for(
                        self.command_queue.get(), 
                        timeout=remaining_time
                    )
                    commands.append(command_data)
                    
                except asyncio.TimeoutError:
                    break
        
        except Exception as e:
            self.logger.error(f"Error getting commands: {e}")
        
        return commands
    
    async def stop(self):
        """Stop command capture"""
        self.logger.info("Stopping command capture...")
        self.monitoring_active = False
        
        # Clean up hook files
        try:
            command_log_file = self.hook_dir / "commands.log"
            if command_log_file.exists():
                command_log_file.unlink()
        except Exception as e:
            self.logger.error(f"Error cleaning up: {e}")
        
        self.logger.info("Command capture stopped")

    def get_active_sessions(self) -> Dict:
        """Get currently active SSH sessions"""
        with self.session_lock:
            return self.ssh_sessions.copy()