import logging
import sys

log = logging.getLogger(__name__)

class logutils():
    def __init__(self, level, logstream, logconsole):
        self.level = level.upper()
        self.logstream = logstream
        self.logconsole = True if logconsole == False else True
        self.dslog = self.dsloginit()

    def dsloginit(self):
        myformatter = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        
        logger = logging.getLogger(__name__)
        
        formatter = logging.Formatter(myformatter)
                
        if self.logstream:
            try:
                logfile = logging.FileHandler(self.logstream)
            except ImportError as ierror:
                log.error(ierror)
                log.error("Unable to create log file. Please check if the given path exists and the user has read/write permission.")
                exit(0)
        else:
        	logfile = logging.StreamHandler()
        	
        if self.level not in levels:
            logfile.setLevel(logging.DEBUG)
            logging.warning("Invalid log level "+self.level+". Log level configured to DEBUG")
        elif self.level == 'INFO':
            logfile.setLevel(logging.INFO)
        elif self.level == 'WARNING':
            logfile.setLevel(logging.WARNING)
        elif self.level == 'ERROR':
            logfile.setLevel(logging.ERROR)
        elif self.level == 'CRITICAL':
            logfile.setLevel(logging.CRITICAL)
        else:
            logfile.setLevel(logging.DEBUG)
                
        logfile.setFormatter(formatter)
        logger.propagate = self.logconsole
        logger.addHandler(logfile)
        
        return logger
        
    def info(self, message):
        return self.dslog.info(message)
        
    def warning(self, message):
        return self.dslog.warning(message)
        
    def error(self, message):
        return self.dslog.error(message)
        
    def critical(self, message):
        return self.dslog.critical(message)
        
    def debug(self, message):
        return self.dslog.debug(message)
