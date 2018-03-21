from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects


# Logs all Cloud SQL Databases with Authorized Networks

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()

alert = False

path = os.path.expanduser('~/python-logs')
logfile = os.path.expanduser('~/python-logs/security.log')

if os.path.isdir(path):
    pass
else:
    os.mkdir(path)


logger = logging.getLogger("Rotating Log")
log_formatter = logging.Formatter('%(asctime)s\t %(levelname)s %(message)s')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(logfile, maxBytes=5*1024*1024, backupCount=5)
handler.setFormatter(log_formatter)
logger.addHandler(handler)

logger.info('-----Checking for SQL unsecure connections-----')
for project in get_projects():
    try:
        service = discovery.build('sqladmin', 'v1beta4')
        request = service.instances().list(project=project)
        response = request.execute()

        if 'items' in response:
            items = response['items']
            for item in items:
                db_name = item['name']
                auth_nets = item['settings']['ipConfiguration']['authorizedNetworks']
                if auth_nets:
                    for auth_net in auth_nets:
                        nets = auth_net['value']
                        logger.warning('Database "{0}" in Project "{1}" has Authorized Networks: {2}'.
                                       format(db_name, project, nets))
                    alert = True
                else:
                    logger.info('Database "{0}" in Project "{1}" has no Authorized Networks'.
                                format(db_name, project))

        else:
            logger.info('0 Databases in Project "{0}"'.format(project))

    except Exception as err:
        logger.error(err)

if alert is False:
    logger.info('No Cloud SQL Authorized Networks found')
