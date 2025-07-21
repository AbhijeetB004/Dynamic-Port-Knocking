#!/usr/bin/env python3
"""
AI Behavioral Analyzer
Uses fine-tuned BERT model to analyze SSH command sequences for malicious behavior.
"""

import logging
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel
import numpy as np
from typing import Dict, List, Optional, Tuple
import re
import json
from pathlib import Path
import time

class BERTClassifier(torch.nn.Module):
    """Custom BERT classifier for SSH command analysis"""
    
    def __init__(self, n_classes: int = 7, model_name: str = 'bert-base-uncased', dropout_rate: float = 0.3):
        super(BERTClassifier, self).__init__()
        self.bert = AutoModel.from_pretrained(model_name)
        self.dropout = torch.nn.Dropout(dropout_rate)
        self.classifier = torch.nn.Linear(self.bert.config.hidden_size, n_classes)
        self.n_classes = n_classes
        
    def forward(self, input_ids, attention_mask):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs.pooler_output
        output = self.dropout(pooled_output)
        return self.classifier(output)

class BehavioralAnalyzer:
    """AI-powered behavioral analysis for SSH commands"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Model configuration
        self.model_path = config.ai_model.model_path
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.max_length = config.ai_model.max_sequence_length
        
        # Class labels
        self.class_labels = [
            'Defense Evasion',
            'Discovery', 
            'Execution',
            'Harmless',
            'Impact',
            'Other',
            'Persistence'
        ]
        
        # Model components
        self.tokenizer = None
        self.model = None
        self.is_loaded = False
        
        # Command preprocessing
        self.command_preprocessor = CommandPreprocessor()
        
        # Performance tracking
        self.inference_times = []
        self.prediction_cache = {}
        
        self.logger.info(f"AI Analyzer initialized (device: {self.device})")
    
    def load_model(self):
        """Load the fine-tuned BERT model"""
        try:
            start_time = time.time()
            
            # Load tokenizer
            self.logger.info("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')
            
            # Load model
            self.logger.info(f"Loading model from {self.model_path}...")
            self.model = BERTClassifier(n_classes=len(self.class_labels))
            
            # Load trained weights
            if Path(self.model_path).exists():
                state_dict = torch.load(self.model_path, map_location=self.device)
                
                # Remove _orig_mod. prefix if present (like in the working code)
                new_state_dict = {}
                for k, v in state_dict.items():
                    if k.startswith('_orig_mod.'):
                        new_k = k[len('_orig_mod.'):]
                    else:
                        new_k = k
                    new_state_dict[new_k] = v
                
                self.model.load_state_dict(new_state_dict)
                self.logger.info(f"Loaded model weights from checkpoint")
            else:
                self.logger.warning(f"Model file not found at {self.model_path}, using untrained model")
            
            self.model.to(self.device)
            self.model.eval()
            
            load_time = time.time() - start_time
            self.is_loaded = True
            
            self.logger.info(f"Model loaded successfully in {load_time:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise
    
    def analyze_commands(self, commands: List[str]) -> Dict:
        """Analyze a sequence of commands for malicious behavior"""
        try:
            if not self.is_loaded:
                raise RuntimeError("Model not loaded. Call load_model() first.")
            
            start_time = time.time()
            
            # Preprocess commands
            processed_text = self.command_preprocessor.preprocess_command_sequence(commands)
            
            # Check cache
            cache_key = hash(processed_text)
            if cache_key in self.prediction_cache:
                return self.prediction_cache[cache_key]
            
            # Tokenize
            inputs = self.tokenizer(
                processed_text,
                add_special_tokens=True,
                max_length=self.max_length,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            
            # Move to device
            input_ids = inputs['input_ids'].to(self.device)
            attention_mask = inputs['attention_mask'].to(self.device)
            
            # Inference
            with torch.no_grad():
                outputs = self.model(input_ids, attention_mask)
                probabilities = torch.sigmoid(outputs).cpu().numpy()[0]
            
            # Create results
            predictions = {
                self.class_labels[i]: float(probabilities[i])
                for i in range(len(self.class_labels))
            }
            
            # Calculate confidence
            max_prob = max(probabilities)
            confidence = float(max_prob)
            
            # Determine dominant category
            dominant_category = self.class_labels[np.argmax(probabilities)]
            
            inference_time = time.time() - start_time
            self.inference_times.append(inference_time)
            
            # Keep only recent inference times for averaging
            if len(self.inference_times) > 100:
                self.inference_times = self.inference_times[-100:]
            
            result = {
                'predictions': predictions,
                'confidence': confidence,
                'dominant_category': dominant_category,
                'inference_time': inference_time,
                'processed_text': processed_text[:200] + "..." if len(processed_text) > 200 else processed_text
            }
            
            # Cache result
            self.prediction_cache[cache_key] = result
            
            # Limit cache size
            if len(self.prediction_cache) > 1000:
                # Remove oldest entries
                oldest_keys = list(self.prediction_cache.keys())[:100]
                for key in oldest_keys:
                    del self.prediction_cache[key]
            
            self.logger.debug(f"Analysis completed in {inference_time:.3f}s - "
                            f"Dominant: {dominant_category} ({confidence:.3f})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing commands: {e}")
            # Return safe default
            return {
                'predictions': {label: 0.0 for label in self.class_labels},
                'confidence': 0.0,
                'dominant_category': 'Other',
                'inference_time': 0.0,
                'processed_text': '',
                'error': str(e)
            }
    
    def get_performance_stats(self) -> Dict:
        """Get performance statistics"""
        if not self.inference_times:
            return {
                'avg_inference_time': 0.0,
                'total_predictions': 0,
                'cache_size': len(self.prediction_cache)
            }
        
        return {
            'avg_inference_time': np.mean(self.inference_times),
            'min_inference_time': min(self.inference_times),
            'max_inference_time': max(self.inference_times),
            'total_predictions': len(self.inference_times),
            'cache_size': len(self.prediction_cache),
            'cache_hit_rate': len(self.prediction_cache) / max(1, len(self.inference_times))
        }

class CommandPreprocessor:
    """Preprocesses SSH commands for AI analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Common command patterns
        self.sensitive_patterns = [
            r'sudo\s+',
            r'su\s+',
            r'chmod\s+[0-9]+',
            r'chown\s+',
            r'passwd\s+',
            r'useradd\s+',
            r'userdel\s+',
            r'usermod\s+',
            r'crontab\s+',
            r'systemctl\s+',
            r'service\s+',
            r'iptables\s+',
            r'netstat\s+',
            r'ss\s+',
            r'lsof\s+',
            r'ps\s+',
            r'kill\s+',
            r'killall\s+',
            r'pkill\s+',
            r'wget\s+',
            r'curl\s+',
            r'scp\s+',
            r'rsync\s+',
            r'tar\s+',
            r'zip\s+',
            r'unzip\s+',
            r'find\s+.*-exec',
            r'xargs\s+',
            r'eval\s+',
            r'exec\s+',
            r'nc\s+',
            r'ncat\s+',
            r'netcat\s+',
            r'socat\s+',
            r'python\s+.*-c',
            r'perl\s+.*-e',
            r'ruby\s+.*-e',
            r'bash\s+.*-c',
            r'sh\s+.*-c',
            r'base64\s+',
            r'openssl\s+',
            r'gpg\s+',
            r'dd\s+',
            r'mount\s+',
            r'umount\s+',
            r'fdisk\s+',
            r'mkfs\s+',
            r'fsck\s+'
        ]
        
        # Compile patterns
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sensitive_patterns]
    
    def preprocess_command_sequence(self, commands: List[str]) -> str:
        """Preprocess a sequence of commands for analysis"""
        try:
            if not commands:
                return ""
            
            processed_commands = []
            
            for command in commands:
                processed_cmd = self._preprocess_single_command(command)
                if processed_cmd:
                    processed_commands.append(processed_cmd)
            
            # Join commands with special separator
            sequence_text = " [SEP] ".join(processed_commands)
            
            # Add sequence context
            context = f"SSH session commands: {sequence_text}"
            
            return context
            
        except Exception as e:
            self.logger.error(f"Error preprocessing commands: {e}")
            return " ".join(commands)
    
    def _preprocess_single_command(self, command: str) -> str:
        """Preprocess a single command"""
        try:
            # Clean and normalize
            command = command.strip()
            if not command:
                return ""
            
            # Remove common prefixes
            command = re.sub(r'^\s*[0-9]+\s+', '', command)  # Remove history numbers
            command = re.sub(r'^\s*\$\s*', '', command)      # Remove prompt
            
            # Normalize whitespace
            command = re.sub(r'\s+', ' ', command)
            
            # Preserve sensitive patterns
            for pattern in self.compiled_patterns:
                if pattern.search(command):
                    # Mark as sensitive
                    command = f"[SENSITIVE] {command}"
                    break
            
            # Handle special characters and operators
            command = self._normalize_special_chars(command)
            
            return command
            
        except Exception as e:
            self.logger.error(f"Error preprocessing command '{command}': {e}")
            return command
    
    def _normalize_special_chars(self, command: str) -> str:
        """Normalize special characters in commands"""
        # Replace common operators with tokens
        replacements = {
            '&&': ' AND ',
            '||': ' OR ',
            '|': ' PIPE ',
            '>': ' REDIRECT_OUT ',
            '>>': ' APPEND_OUT ',
            '<': ' REDIRECT_IN ',
            '2>': ' REDIRECT_ERR ',
            '2>&1': ' REDIRECT_ERR_OUT ',
            ';': ' SEMICOLON ',
            '&': ' BACKGROUND ',
            '$(': ' SUBSHELL_START ',
            '`': ' BACKTICK ',
            '\\': ' ESCAPE '
        }
        
        for old, new in replacements.items():
            command = command.replace(old, new)
        
        return command
    
