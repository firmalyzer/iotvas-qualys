import sys
import os
import logging
import logging.handlers
from logging.handlers import TimedRotatingFileHandler
import base64

import iotvas
from config import app_config


def get_logger(name, level, folder):
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(name)
    logger.setLevel(level)
    file_handler = TimedRotatingFileHandler(os.path.join(folder, "iotvas-qualys"),
                                           when = 'd',
                                           interval = 1,
                                           backupCount = 0)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger

def get_iotvas_client():
    config = iotvas.Configuration("iotvas")
    config.host = app_config['iotvas_url']
    config.api_key = app_config['iotvas_apikey']
    client = iotvas.ApiClient(configuration=config)
    client.default_headers['x-api-key'] = config.api_key
    return client

