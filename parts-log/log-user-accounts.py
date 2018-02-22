from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects
from pprint import pprint


# logs User Accounts not part of GCP Organization

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
    project_name = 'projects/' + project
    service = discovery.build('cloudresourcemanager', 'v1')
    request = service.projects().getIamPolicy(resource=project, body={})
    response = request.execute()
    bindings = response['bindings']
    print('@' * 100)
    print(project)
    print('@' * 100)

    for binding in bindings:
        # print(binding['members'])
        for member in binding['members']:
            print(member)
