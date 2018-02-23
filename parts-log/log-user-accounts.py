from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects


# logs User Accounts not part of the specified GCP Organization

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()

alert = False
domain = '<example.com>'

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
    user_list = []
    service = discovery.build('cloudresourcemanager', 'v1')
    request = service.projects().getIamPolicy(resource=project, body={})
    response = request.execute()
    bindings = response['bindings']

    for binding in bindings:
        for member in binding['members']:
            if member.startswith('user:') and domain not in member:
                alert = True
                if member not in user_list:
                    logger.warning('Project "{0}" contains non-organizational account "{1}"'.format(project, member))
                    user_list.append(member)
                else:
                    pass

if alert is False:
    logger.info('No non-organizational users found')
