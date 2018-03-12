from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from googleapiclient.errors import HttpError
from gcp import get_key, get_projects


# Logs all Cloud SQL Databases without enforced SSL Connections

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

for project in get_projects():
    print(project)

    try:
        service = discovery.build('sqladmin', 'v1beta4')
        request = service.instances().list(project=project)
        response = request.execute()

        if 'items' in response:
            items = response['items']
            for item in items:

                if 'requireSsl' not in item['settings']['ipConfiguration']:
                    db_name = item['name']
                    logger.warning('Database "{0}" in Project "{1}" does not have SSL enforced'.
                                   format(db_name, project))

        else:
            logger.info('0 Databases in Project "{0}"'.format(project))

    except HttpError as he:
        if he.resp.status == 403:
            logger.error('Access Denied.  Check Cloud SQL Permissions on Project "{0}"'.format(project))

    except Exception:
        logger.error('Cloud SQL Unsecure Connections - Unknown error in project "{0}".  '
                     'Please run manually'.format(project))
