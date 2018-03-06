from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

from pprint import pprint

# logs all VPCs with Auto-Created Subnets (contains all Regions) and Custom VPCs with non-US Subnets

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


for project_name in get_projects():
    service = discovery.build('compute', 'v1')
    request = service.networks().list(project=project_name)
    response = request.execute()
    try:
        items = response['items']
        # print(project_name)
        # pprint(items)

        for item in items:
            vpc = item['name']
            autocreate = item['autoCreateSubnetworks']

            if autocreate is True:
                alert = True
                logger.warning('VPC "{0}" contains Auto-Created Subnets in project "{1}"'.format(vpc, project_name))

            else:
                subnetworks = item['subnetworks']
                for subnetwork in subnetworks:
                    print(subnetwork)

            # if vpc == 'default':
            #     alert = True
            #     logger.warning('Default VPC Network "{0}" found in project "{1}"'.format(vpc, project_name))

    except KeyError:
        logger.info('0 VPCs found in project "{0}"'.format(project_name))

    except Exception:
        logger.error('Default VPC Network - Unknown error.  Please run manually')

if alert is False:
    logger.info('No Default VPCs found')
