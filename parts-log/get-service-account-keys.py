from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects
from datetime import datetime
from dateutil.relativedelta import relativedelta


# Logs all Service Accounts Keys that are older than 90 days

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

logger.info('-----Checking Service Account Key age-----')
for project in get_projects():
    project_name = 'projects/' + project
    try:
        service = discovery.build('iam', 'v1')
        request = service.projects().serviceAccounts().list(name=project_name)
        response = request.execute()
        accounts = response['accounts']

        for account in accounts:
            serviceaccount = project_name + '/serviceAccounts/' + account['email']
            request = service.projects().serviceAccounts().keys().list(name=serviceaccount)
            response = request.execute()
            keys = response['keys']

            for key in keys:
                keyname = key['name']
                startdate = datetime.strptime(key['validAfterTime'], '%Y-%m-%dT%H:%M:%SZ')
                enddate = datetime.strptime(key['validBeforeTime'], '%Y-%m-%dT%H:%M:%SZ')
                key_age_years = relativedelta(enddate, startdate).years

                if key_age_years > 180:
                    key_age_days = relativedelta(datetime.utcnow(), startdate).days
                    if key_age_days > 1:
                        alert = True
                        logger.warning('Service Account key is older than 180 days: {0}'.format(keyname))

    except KeyError:
        logger.info('No Service Accounts found in project "{0}"'.format(project))

    except Exception as err:
        logger.error(err)

if alert is False:
    logger.info(' No Service Account Keys older than 180 days found')
