import logging
import os
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler

class LoggerConfig:
    """Class to handle logging configuration for different modules."""

    @staticmethod
    def configure_logger(module_name, log_dir='logs', log_level=logging.DEBUG):
        """Configure logger for a specific module and log it to a separate file."""
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Set up rotating log files (max size 10MB, keep 5 backup files)
        log_file = os.path.join(log_dir, f'{module_name}.log')
        handler = RotatingFileHandler(log_file, maxBytes=10**7, backupCount=5)

        # Create a logger for the specific module
        logger = logging.getLogger(module_name)
        logger.setLevel(log_level)

        # Set up the file handler and console handler
        handler.setLevel(log_level)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Formatter for log output
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers to the logger
        logger.addHandler(handler)
        logger.addHandler(console_handler)

        return logger


    # @staticmethod
    # def setup_queue_logger(module_name, log_queue, log_level=logging.DEBUG):
    #     """Used in subprocess: direct log to multiprocessing queue"""
    #     logger = logging.getLogger(module_name)
    #     logger.setLevel(log_level)

    #     # 清除旧的 handler（防止重复）
    #     logger.handlers.clear()

    #     queue_handler = QueueHandler(log_queue)
    #     logger.addHandler(queue_handler)

    #     return logger

    # @staticmethod
    # def start_log_listener(log_queue, module_name, log_dir='logs', log_level=logging.DEBUG):
    #     """Start a queue listener in main process, write to file & console."""
    #     if not os.path.exists(log_dir):
    #         os.makedirs(log_dir)

    #     log_file = os.path.join(log_dir, f'{module_name}.log')
    #     file_handler = RotatingFileHandler(log_file, maxBytes=10**7, backupCount=5)
    #     console_handler = logging.StreamHandler()

    #     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #     file_handler.setFormatter(formatter)
    #     console_handler.setFormatter(formatter)

    #     file_handler.setLevel(log_level)
    #     console_handler.setLevel(logging.INFO)

    #     listener = QueueListener(log_queue, file_handler, console_handler)
    #     listener.start()
    #     return listener