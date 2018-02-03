from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

"""logs all Default VPC Networks"""

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()
alert = False

path = os.path.join(os.path.dirname(__file__), 'logs/')
logfile = os.path.join(path, 'google-security.log')

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


for project_name in get_projects():
    service = discovery.build('compute', 'v1')
    request = service.networks().list(project=project_name)
    response = request.execute()
    try:
        items = response['items']
        for item in items:
            vpc = item['name']

            if vpc == 'default':
                alert = True
                logger.warning('Default VPC Network "{0}" found in project "{1}"'.format(vpc, project_name))
    except:
        pass

if alert is False:
    logger.info('No Default VPCs found')
