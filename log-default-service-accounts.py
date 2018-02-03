from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

"""logs all Service Accounts from the Service Account page"""

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

for project in get_projects():
    project_name = 'projects/' + project
    service = discovery.build('iam', 'v1')
    request = service.projects().serviceAccounts().list(name=project_name)
    response = request.execute()

    if len(response) > 0:
        accounts = response['accounts']

        for account in accounts:
            serviceaccount = account['email']

            if 'gserviceaccount.com' in serviceaccount and 'iam' not in serviceaccount:
                alert = True
                logger.warning('Default Service Account "{0}" found in project "{1}"'.
                               format(serviceaccount, project))

if alert is False:
    logger.info('No Default Service Accounts found')
