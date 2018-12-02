"""
This will help to log all sorts of messages that vault scanner emits.

USAGE:
    Initialize -
            import logging
            LOGGER = logging.getLogger(__name__)

    Logging -
            LOGGER.info("Any messages you want to log")

There are different modes for logging like info, debug etc.
For more details read: https://docs.python.org/3/library/logging.html
"""
import logging
import logging.handlers


class Logger:

    @staticmethod
    def create_logger(debug_filename, logger_name):

        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        formatter = logging.Formatter(fmt='%(asctime)s %(levelname)s:%(name)s:%(funcName)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')

        debug_log_handler = logging.handlers.RotatingFileHandler(debug_filename, encoding='utf-8', mode="w")
        debug_log_handler.setLevel(logging.DEBUG)
        debug_log_handler.setFormatter(formatter)
        logger.addHandler(debug_log_handler)

        return logger
