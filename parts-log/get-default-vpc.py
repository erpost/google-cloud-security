from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects


# logs all Default VPC Networks

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

logger.info('-----Checking for default VPCs-----')
for project in get_projects():
    try:
        service = discovery.build('compute', 'v1')
        request = service.networks().list(project=project)
        response = request.execute()
        items = response['items']

        for item in items:
            vpc = item['name']
            autocreate = item['autoCreateSubnetworks']

            if vpc == 'default' and autocreate is True:
                alert = True
                logger.warning(' Default VPC Network "{0}" found in project "{1}"'.format(vpc, project))

    except KeyError:
        logger.info('No VPCs found in project "{0}"'.format(project))

    except Exception as err:
        logger.error(err)

if alert is False:
    logger.info('No Default VPCs found')
