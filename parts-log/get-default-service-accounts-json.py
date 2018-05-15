from googleapiclient import discovery
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

import os
import logging
import logmatic

# logs all Default Service Accounts from the Service Account page

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
    project_name = 'projects/' + project
    try:
        service = discovery.build('iam', 'v1')
        request = service.projects().serviceAccounts().list(name=project_name)
        response = request.execute()
        accounts = response['accounts']

        for account in accounts:
            serviceaccount = account['email']

            if 'gserviceaccount.com' in serviceaccount and 'iam' not in serviceaccount:
                logger.warning('default service account found', extra={'rule': 'default service accounts',
                                                                            'projectName': project,
                                                                            'resourceType': 'service_account',
                                                                            'resourceName': serviceaccount})
    except KeyError:
        logger.info('no service accounts found', extra={'rule': 'default service accounts',
                                                                            'projectName': project,
                                                                            'resourceType': 'service_account',
                                                                            'resourceName': 'n/a'})

    except Exception as err:
        logger.error(err, extra={'rule': 'default service accounts',
                                 'projectName': project,
                                 'resourceType': 'service_account'})
