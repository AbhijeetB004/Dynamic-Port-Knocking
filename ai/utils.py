import logging


def setup_logging(logging_config):
    """
    Setup logging configuration for the monitoring system.
    Expects a SimpleNamespace with attributes: 'level' and 'log_file'.
    Returns a logger instance.
    """
    log_level = getattr(logging, getattr(logging_config, 'level', 'INFO').upper(), logging.INFO)
    log_file = getattr(logging_config, 'log_file', 'monitor.log')
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger('SSHBehavioralMonitor')
    return logger


def validate_config(config):
    """
    Validate the main configuration object. Raises ValueError if required fields are missing.
    """
    required_sections = [
        'logging', 'capture', 'ai_model', 'response', 'analysis', 'thresholds', 'session', 'monitoring'
    ]
    for section in required_sections:
        if not hasattr(config, section):
            raise ValueError(f"Missing required config section: {section}")
    # Optionally, add more detailed checks here
