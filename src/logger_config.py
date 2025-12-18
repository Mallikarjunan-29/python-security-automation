import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger

def get_logger(name):
    #Create Logger
    logger=logging.getLogger(name)

    #Create File Hander
    current_path=os.getcwd()
    log_path=os.path.join(current_path,"logs")
    os.makedirs(log_path,exist_ok=True)
    log_timestamp=time.strftime("%Y-%m-%d")
    file_path=os.path.join(log_path,f"ai_log_{log_timestamp}.log")
    fh=RotatingFileHandler(file_path,"a",5_000_000,3)
    fh.setLevel(logging.DEBUG)

    #Create Stream handler
    ch=logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    #Set Formmater for Handlers
    formatter_old=logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(funcName)s:%(lineno)d  %(message)s',
                                          rename_fields={
                                              'asctime': 'timestamp',
                                              'levelname':'level'
                                          })
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)

    #Attach File and Stream handlers to logger
    if not logger.handlers:
        logger.addHandler(ch)
        logger.addHandler(fh)

    #Set Logging level
    logger.setLevel(logging.DEBUG)
    return logger
