from googleapiclient import discovery
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

import os
import logging
import logmatic

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
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(logfile, maxBytes=5*1024*1024, backupCount=5)
handler.setFormatter(logmatic.JsonFormatter())
logger.addHandler(handler)

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
                logger.warning('default vpc found', extra={'rule': 'default vpc',
                                                                       'projectName': project,
                                                                       'resourceType': 'default_vpc',
                                                                       'resourceName': vpc})

    except KeyError:
        logger.info('no vpc found', extra={'rule': 'default vpc',
                                           'projectName': project,
                                           'resourceType': 'default_vpc',
                                           'resourceName': 'n/a'})

    except Exception as err:
        logger.error(err, extra={'rule': 'default vpc',
                                 'projectName': project,
                                 'resourceType': 'default_vpc'})
