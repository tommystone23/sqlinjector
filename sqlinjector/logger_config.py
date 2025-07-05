# Log to syslog until we can log to PTT core web app

import logging
import logging.handlers

logger = logging.getLogger('SQLInjector')
logger.setLevel(logging.INFO)
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)