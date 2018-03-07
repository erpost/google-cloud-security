from googleapiclient import discovery
import os
import logging
import re
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects


# logs all non-US Subnets

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
    service = discovery.build('compute', 'v1')
    request = service.networks().list(project=project)
    response = request.execute()
    try:
        items = response['items']

        for item in items:
            vpc = item['name']
            subnetworks = item['subnetworks']

            for subnetwork in subnetworks:
                subnets = re.findall('regions/(.*)/subnetworks', subnetwork)

                for subnet in subnets:
                    if 'us-' not in subnet:
                        alert = True
                        logger.warning('| Non-US subnet "{0}" found in VPC "{1}" in project "{2}"'.format(subnet, vpc, project))

    except KeyError:
        logger.info('| 0 VPCs found in project "{0}"'.format(project))

    except Exception:
        logger.error('| Non-US subnets - Unknown error.  Please run manually')

if alert is False:
    logger.info('| No non-US subnets found')
