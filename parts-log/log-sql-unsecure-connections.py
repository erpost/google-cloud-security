from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from googleapiclient.errors import HttpError
from gcp import get_key, get_projects

from pprint import pprint

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

projects = ['allofus-bigquery', 'allofus-forseti']

for project in projects:
# for project in get_projects():
#     print(project)

    try:
        service = discovery.build('sqladmin', 'v1beta4')
        request = service.instances().list(project=project)
        response = request.execute()
        items = response['items']

        for item in items:
            print(75 * '*')
            print(project)
            if item['name']:
                print(item['name'])
                if item['settings']['ipConfiguration']['requireSsl']:
                    print(item['settings']['ipConfiguration']['requireSsl'])
                else:
                    print('Missing SSL Key')
            # ssl_enforced = item['settings']['ipConfiguration']['requireSsl']
            # db_name = item['name']
            # logger.warning('Database "{0}" in Project "{1}" has SSL configured to: "{2}"'.format(db_name, project, ssl_enforced))

    except KeyError:
        logger.info('0 Databases in Project "{0}"'.format(project))

    except HttpError as he:
        if he.resp.status == 403:
            logger.error('Access Denied error.  Check Cloud SQL Permissions on Project "{0}"'.format(project))

    except Exception:
        logger.error('Cloud SQL Unsecure Connections - Unknown error in project "{0}".  Please run manually'.format(project))
