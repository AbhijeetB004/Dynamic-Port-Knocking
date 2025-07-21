#!/usr/bin/env python3
"""
Telegram Alert Module
Sends security alerts to admin via Telegram bot when violations are detected.
"""

import asyncio
import aiohttp
import logging
from typing import Dict
from datetime import datetime
import html

class TelegramAlert:
    """Handles Telegram notifications for security alerts"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger("telegram_alert")
        self.logger.setLevel(logging.DEBUG)

        # Set up logging to stdout if not configured externally
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        # Telegram configuration
        self.bot_token = getattr(config.telegram, 'bot_token', None)
        self.chat_id = getattr(config.telegram, 'chat_id', None)
        self.enabled = getattr(config.telegram, 'enabled', False)
        
        if self.enabled and (not self.bot_token or not self.chat_id):
            self.logger.warning("Telegram alerts enabled but bot_token or chat_id not configured")
            self.enabled = False
        
        self.logger.info(f"Telegram alerts {'enabled' if self.enabled else 'disabled'}")
    
    async def send_alert(self, alert_type: str, session_info: Dict, risk_score: float, 
                         analysis_result: Dict, action_taken: str):
        """Send security alert via Telegram"""
        if not self.enabled:
            return
        
        try:
            message = self._format_alert_message(alert_type, session_info, risk_score, 
                                                 analysis_result, action_taken)
            
            self.logger.debug(f"Telegram message content: {repr(message)}")
            
            await self._send_telegram_message(message)
            
            self.logger.info(f"Telegram alert sent: {alert_type}")
            
        except Exception as e:
            self.logger.error(f"Error sending Telegram alert: {e}")
    
    def _format_alert_message(self, alert_type: str, session_info: Dict, risk_score: float,
                              analysis_result: Dict, action_taken: str) -> str:
        """Format alert message for Telegram (safe plain text)"""
        # Safely extract and clean values
        user = str(session_info.get('user', 'unknown')).strip()
        ip_address = str(session_info.get('ip_address', 'unknown')).strip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Clean the alert_type and action_taken to avoid special characters
        alert_type_clean = str(alert_type).replace('_', ' ').upper()
        action_taken_clean = str(action_taken).replace('_', ' ').upper()
        
        # Log the raw data for debugging
        self.logger.debug(f"Raw session_info: {session_info}")
        self.logger.debug(f"Raw analysis_result: {analysis_result}")
        
        # Create a basic message first
        basic_message = (
            f"[{timestamp}]\n"
            f"ALERT TYPE: {alert_type_clean}\n"
            f"User: {user}\n"
            f"IP Address: {ip_address}\n"
            f"Risk Score: {risk_score:.2f}\n"
            f"Action Taken: {action_taken_clean}"
        )
        
        # Log message length and content at critical points
        self.logger.debug(f"Basic message length: {len(basic_message)}")
        self.logger.debug(f"Basic message around offset 400: {repr(basic_message[390:410])}")
        
        # Clean any problematic characters that might cause entity parsing issues
        # Remove common characters that could be interpreted as markdown/HTML
        problematic_chars = ['*', '_', '`', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|', '{', '}', '~', '>', '<', '&', '"', "'"]
        clean_message = basic_message
        for char in problematic_chars:
            clean_message = clean_message.replace(char, f" {char} ")
        
        # Normalize whitespace
        clean_message = ' '.join(clean_message.split())
        
        # Final safety check - if message is still too long or problematic, truncate
        if len(clean_message) > 4000:  # Telegram limit is 4096, leave some buffer
            clean_message = clean_message[:3900] + "... (truncated)"
        
        self.logger.debug(f"Final message length: {len(clean_message)}")
        self.logger.debug(f"Final message: {repr(clean_message)}")
        
        return clean_message
    
    async def _send_telegram_message(self, message: str):
        """Send message via Telegram Bot API (plain text)"""
        if not self.bot_token or not self.chat_id:
            return
        
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        
        # First attempt with the full message
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'disable_web_page_preview': True,
            'disable_notification': False
        }
        
        # Add timeout and better error handling
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        self.logger.debug("Telegram message sent successfully")
                        return
                    else:
                        response_text = await response.text()
                        self.logger.error(f"Telegram API error: {response.status} - {response_text}")
                        
                        # If it's a parsing error, try sending a simplified message
                        if "can't parse entities" in response_text.lower():
                            self.logger.info("Attempting to send simplified message")
                            await self._send_simplified_message(message)
                        
            except asyncio.TimeoutError:
                self.logger.error("Telegram API request timed out")
            except Exception as e:
                self.logger.error(f"Error sending to Telegram API: {e}")
    
    async def _send_simplified_message(self, original_message: str):
        """Send a simplified version of the message if the original fails"""
        if not self.bot_token or not self.chat_id:
            return
        
        # Create a very simple message with just the basics
        lines = original_message.split('\n')
        simplified = "SECURITY ALERT\n"
        
        # Extract key information safely
        for line in lines:
            if 'ALERT TYPE:' in line:
                simplified += f"Type: {line.split(':', 1)[1].strip()}\n"
            elif 'User:' in line:
                simplified += f"User: {line.split(':', 1)[1].strip()}\n"
            elif 'IP Address:' in line:
                simplified += f"IP: {line.split(':', 1)[1].strip()}\n"
            elif 'Risk Score:' in line:
                simplified += f"Risk: {line.split(':', 1)[1].strip()}\n"
            elif 'Action Taken:' in line:
                simplified += f"Action: {line.split(':', 1)[1].strip()}\n"
        
        # Remove any remaining problematic characters
        simplified = ''.join(char if char.isalnum() or char in ' \n:.-' else ' ' for char in simplified)
        
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            'chat_id': self.chat_id,
            'text': simplified.strip(),
            'disable_web_page_preview': True,
            'disable_notification': False
        }
        
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        self.logger.info("Simplified Telegram message sent successfully")
                    else:
                        response_text = await response.text()
                        self.logger.error(f"Simplified message also failed: {response.status} - {response_text}")
            except Exception as e:
                self.logger.error(f"Error sending simplified message: {e}")
    
    async def send_session_terminated_alert(self, session_info: Dict, risk_score: float, 
                                            analysis_result: Dict):
        """Send alert when session is terminated"""
        await self.send_alert("SESSION_TERMINATED", session_info, risk_score, 
                              analysis_result, "TERMINATED")
    
    async def send_blacklist_alert(self, session_info: Dict, risk_score: float, 
                                   analysis_result: Dict):
        """Send alert when IP is blacklisted"""
        await self.send_alert("IP_BLACKLISTED", session_info, risk_score, 
                              analysis_result, "BLACKLISTED")
    
    async def send_warning_alert(self, session_info: Dict, risk_score: float, 
                                 analysis_result: Dict, warning_count: int):
        """Send alert when warning is issued"""
        await self.send_alert(f"WARNING_{warning_count}", session_info, risk_score, 
                              analysis_result, f"WARNING_{warning_count}")