#!/usr/bin/env python3
"""
SSH Behavioral Monitoring System
Main application that orchestrates command capture, AI analysis, and response actions.
"""

import asyncio
import logging
import json
import signal
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import time

from cmdcap import SSHCommandCapture
from beh import BehavioralAnalyzer
from response import ResponseEngine
from config import Config
from utils import setup_logging, validate_config
from telegram_alert import TelegramAlert

@dataclass
class SessionInfo:
    """Information about an active SSH session"""
    session_id: str
    user: str
    ip_address: str
    start_time: datetime
    command_history: List[str]
    risk_scores: List[float]
    blacklisted: bool = False
    warnings_issued: int = 0
    last_activity: datetime = None

    def __post_init__(self):
        if self.last_activity is None:
            self.last_activity = self.start_time

class SSHBehavioralMonitor:
    """Main behavioral monitoring system"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = Config(config_path)
        self.logger = setup_logging(self.config.logging)
        
        # Core components
        self.command_capture = SSHCommandCapture(self.config)
        self.ai_analyzer = BehavioralAnalyzer(self.config)
        self.response_engine = ResponseEngine(self.config)
        
        # Session management
        self.active_sessions: Dict[str, SessionInfo] = {}
        self.session_lock = threading.Lock()
        
        # Background tasks
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.running = False
        
        # Performance metrics
        self.stats = {
            'total_commands': 0,
            'total_sessions': 0,
            'blacklisted_ips': 0,
            'warnings_issued': 0,
            'start_time': datetime.now()
        }
        
        self.logger.info("SSH Behavioral Monitor initialized")
    
    async def start(self):
        """Start the monitoring system"""
        try:
            self.running = True
            self.logger.info("Starting SSH Behavioral Monitor...")
            
            # Validate configuration
            validate_config(self.config)
            
            # Initialize components
            await self._initialize_components()
            
            # Start background tasks
            tasks = [
                asyncio.create_task(self._command_processing_loop()),
                asyncio.create_task(self._session_cleanup_loop()),
                asyncio.create_task(self._stats_reporting_loop())
            ]
            
            self.logger.info("SSH Behavioral Monitor started successfully")
            
            # Wait for all tasks to complete
            await asyncio.gather(*tasks)
            
        except Exception as e:
            self.logger.error(f"Error starting monitor: {e}")
            raise
    
    async def _initialize_components(self):
        """Initialize all system components"""
        try:
            # Load AI model
            self.logger.info("Loading AI model...")
            await asyncio.get_event_loop().run_in_executor(
                self.executor, self.ai_analyzer.load_model
            )
            
            # Initialize command capture
            self.logger.info("Initializing command capture...")
            await self.command_capture.initialize()
            
            # Initialize response engine
            self.logger.info("Initializing response engine...")
            await self.response_engine.initialize()
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")
            raise
    
    async def _command_processing_loop(self):
        """Main loop for processing captured commands"""
        self.logger.info("Starting command processing loop...")
        
        while self.running:
            try:
                # Get captured commands
                commands = await self.command_capture.get_commands(timeout=1.0)
                self.logger.info(f"Processing commands: {commands}")
                for cmd_data in commands:
                    await self._process_command(cmd_data)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in command processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _process_command(self, cmd_data: Dict):
        """Process a single captured command"""
        try:
            session_id = cmd_data.get('session_id')
            command = cmd_data.get('command', '').strip()
            user = cmd_data.get('user', 'unknown')
            ip_address = cmd_data.get('ip_address', 'unknown')
            
            if not command or not session_id:
                return
            
            # Update session info
            with self.session_lock:
                if session_id not in self.active_sessions:
                    self.active_sessions[session_id] = SessionInfo(
                        session_id=session_id,
                        user=user,
                        ip_address=ip_address,
                        start_time=datetime.now(),
                        command_history=[],
                        risk_scores=[]
                    )
                    self.stats['total_sessions'] += 1
                
                session = self.active_sessions[session_id]
                
                # Skip if session is blacklisted
                if session.blacklisted:
                    return
                
                # Update session
                session.command_history.append(command)
                session.last_activity = datetime.now()
                
                # Maintain sliding window
                if len(session.command_history) > self.config.analysis.max_command_history:
                    session.command_history = session.command_history[-self.config.analysis.max_command_history:]
                    session.risk_scores = session.risk_scores[-self.config.analysis.max_command_history:]
            
            self.stats['total_commands'] += 1
            
            # Analyze command sequence if we have enough context
            if len(session.command_history) >= self.config.analysis.min_commands_for_analysis:
                await self._analyze_session_behavior(session)
            
            self.logger.debug(f"Processed command: {command[:50]}... for session {session_id}")
            
        except Exception as e:
            self.logger.error(f"Error processing command: {e}")
    
    async def _analyze_session_behavior(self, session: SessionInfo):
        """Analyze behavior for a session and take appropriate action"""
        try:
            # Get recent commands for analysis
            recent_commands = session.command_history[-self.config.analysis.analysis_window:]
            
            # Run AI analysis
            analysis_result = await asyncio.get_event_loop().run_in_executor(
                self.executor, self.ai_analyzer.analyze_commands, recent_commands
            )
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(analysis_result)
            session.risk_scores.append(risk_score)
            
            # Log analysis results
            self.logger.debug(f"Session {session.session_id} analysis: "
                            f"risk_score={risk_score:.3f}, "
                            f"predictions={analysis_result.get('predictions', {})}")
            
            # Determine response based on risk score
            await self._handle_risk_assessment(session, risk_score, analysis_result)
            
        except Exception as e:
            self.logger.error(f"Error analyzing session behavior: {e}")
    
    def _calculate_risk_score(self, analysis_result: Dict) -> float:
        """Calculate overall risk score from AI analysis results"""
        predictions = analysis_result.get('predictions', {})
        
        # Weight different categories based on severity
        weights = {
            'Defense Evasion': 0.9,
            'Persistence': 0.8,
            'Impact': 0.95,
            'Execution': 0.7,
            'Discovery': 0.5,
            'Other': 0.6,
            'Harmless': -0.1  # Negative weight for harmless activities
        }
        
        risk_score = 0.0
        for category, probability in predictions.items():
            weight = weights.get(category, 0.5)
            risk_score += probability * weight
        
        # Normalize to [0, 1] range
        risk_score = max(0.0, min(1.0, risk_score))
        
        return risk_score
    
    async def _handle_risk_assessment(self, session: SessionInfo, risk_score: float, analysis_result: Dict):
        """Handle the response based on risk assessment"""
        try:
            # Check thresholds
            if risk_score >= self.config.thresholds.blacklist_threshold:
                await self._blacklist_session(session, risk_score, analysis_result)
            elif risk_score >= self.config.thresholds.warning_threshold:
                await self._warn_session(session, risk_score, analysis_result)
            elif risk_score >= self.config.thresholds.monitor_threshold:
                await self._monitor_session(session, risk_score, analysis_result)
            
        except Exception as e:
            self.logger.error(f"Error handling risk assessment: {e}")
    
    async def _blacklist_session(self, session: SessionInfo, risk_score: float, analysis_result: Dict):
        """Blacklist a session due to high risk"""
        try:
            session.blacklisted = True
            self.stats['blacklisted_ips'] += 1
            
            # Log security event
            self.logger.warning(f"BLACKLISTED SESSION: {session.session_id} "
                              f"(user: {session.user}, ip: {session.ip_address}) "
                              f"Risk Score: {risk_score:.3f}")
            
            # Execute response
            await self.response_engine.blacklist_ip(
                session.ip_address, 
                reason=f"High risk behavior detected (score: {risk_score:.3f})",
                session_info=asdict(session),
                analysis_result=analysis_result
            )
            
            # Terminate session
            await self.response_engine.terminate_session(session.session_id)
            
            # Send Telegram alert for session termination
            await self.response_engine.telegram_alert.send_session_terminated_alert(
                asdict(session), risk_score, analysis_result
            )
            
        except Exception as e:
            self.logger.error(f"Error blacklisting session: {e}")
    
    async def _warn_session(self, session: SessionInfo, risk_score: float, analysis_result: Dict):
        """Issue warning for medium risk behavior"""
        try:
            session.warnings_issued += 1
            self.stats['warnings_issued'] += 1
            
            self.logger.warning(f"WARNING ISSUED: {session.session_id} "
                              f"(user: {session.user}, ip: {session.ip_address}) "
                              f"Risk Score: {risk_score:.3f}")
            
            # Execute warning response
            await self.response_engine.warn_user(
                session.session_id,
                risk_score,
                analysis_result.get('predictions', {}),
                session.warnings_issued
            )
            
            # Blacklist after too many warnings
            if session.warnings_issued >= self.config.thresholds.max_warnings:
                await self._blacklist_session(session, risk_score, analysis_result)
            
        except Exception as e:
            self.logger.error(f"Error warning session: {e}")
    
    async def _monitor_session(self, session: SessionInfo, risk_score: float, analysis_result: Dict):
        """Increase monitoring for low-medium risk behavior"""
        self.logger.info(f"MONITORING: {session.session_id} "
                        f"(user: {session.user}, ip: {session.ip_address}) "
                        f"Risk Score: {risk_score:.3f}")
    
    async def _session_cleanup_loop(self):
        """Clean up inactive sessions"""
        while self.running:
            try:
                current_time = datetime.now()
                cleanup_threshold = current_time - timedelta(
                    seconds=self.config.session.inactive_timeout
                )
                
                with self.session_lock:
                    sessions_to_remove = []
                    for session_id, session in self.active_sessions.items():
                        if session.last_activity < cleanup_threshold:
                            sessions_to_remove.append(session_id)
                    
                    for session_id in sessions_to_remove:
                        del self.active_sessions[session_id]
                        self.logger.debug(f"Cleaned up inactive session: {session_id}")
                
                await asyncio.sleep(self.config.session.cleanup_interval)
                
            except Exception as e:
                self.logger.error(f"Error in session cleanup: {e}")
                await asyncio.sleep(60)
    
    async def _stats_reporting_loop(self):
        """Periodically report system statistics"""
        while self.running:
            try:
                await asyncio.sleep(self.config.monitoring.stats_interval)
                
                with self.session_lock:
                    active_sessions_count = len(self.active_sessions)
                
                uptime = datetime.now() - self.stats['start_time']
                
                self.logger.info(f"STATS: Active Sessions: {active_sessions_count}, "
                               f"Total Commands: {self.stats['total_commands']}, "
                               f"Blacklisted IPs: {self.stats['blacklisted_ips']}, "
                               f"Warnings: {self.stats['warnings_issued']}, "
                               f"Uptime: {uptime}")
                
            except Exception as e:
                self.logger.error(f"Error in stats reporting: {e}")
    
    async def stop(self):
        """Stop the monitoring system"""
        self.logger.info("Stopping SSH Behavioral Monitor...")
        self.running = False
        
        # Stop components
        await self.command_capture.stop()
        await self.response_engine.stop()
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        self.logger.info("SSH Behavioral Monitor stopped")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}. Shutting down...")
    sys.exit(0)

async def main():
    """Main entry point"""
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize and start monitor
    monitor = SSHBehavioralMonitor()
    
    try:
        await monitor.start()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        await monitor.stop()

if __name__ == "__main__":
    asyncio.run(main())