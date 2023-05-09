from dataclasses import dataclass
import logging
import colorlog

logging_levels = ["INFO", "WARN", "DEBUG", "ERROR"]

@dataclass(kw_only=True)
class LogHandler:
    """
        Class responsible for creating logger handlers
        
        Args:
            log_file_name (str): name of the logger out file
            console_log_fmt (str): Console logger format (default: %(log_color)s[%(asctime)s] - %(levelname)s - %(message)s)
            file_log_fmt (str): File logger format (default: [%(asctime)s] - %(levelname)s - %(message)s)
            datetimefmt (str): Datetime logger format (default: %Y-%m-%d %H:%M:%S)
            level (str): Logger level (default: DEBUG)
    """

    log_file_name: str
    console_log_fmt: str = "%(log_color)s[%(asctime)s] - %(levelname)s - %(message)s"
    file_log_fmt: str = "[%(asctime)s] - %(levelname)s - %(message)s"
    datetimefmt: str = "%Y-%m-%d %H:%M:%S"
    level: str = "DEBUG"

    def setup_logger(self) -> logging.RootLogger:
        """
            Setup the logging module.

        Returns:
            logging.RootLogger: Logger object
        """ 

        logger = logging.getLogger()
        logger.setLevel(self.level)

        file_handler = self.create_file_handler()
        console_handler = self.create_console_handler()

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        return logger

    def create_console_handler(self) -> logging.StreamHandler:
        """
            Create a console handler.

        Returns:
            logging.StreamHandler: Console handler
        """

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self.colored_formatter())

        return console_handler

    def create_file_handler(self) -> logging.FileHandler:
        """
            Create a console handler.

        Returns:
            logging.FileHandler: File handler
        """

        file_handler = logging.FileHandler(f"output\{self.log_file_name}")
        file_handler.setFormatter(logging.Formatter(self.file_log_fmt, datefmt=self.datetimefmt))
        
        return file_handler

    def colored_formatter(self) -> colorlog.formatter.ColoredFormatter:
        """
            Create a colored formatter for logging console messages.

        Returns:
            colorlog.formatter.ColoredFormatter: Colorlog object
        """

        return colorlog.ColoredFormatter(
            self.console_log_fmt,
            datefmt=self.datetimefmt
        )
