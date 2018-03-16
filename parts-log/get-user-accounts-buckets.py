from google.cloud import storage
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects


# logs User Accounts tied to GCP Buckets that are not part of the specified GCP Organization

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()


alert = False
domain = 'nih.gov'

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

logger.info('-----Checking for non-organizational accounts on buckets-----')
for project in get_projects():
    try:
        storage_client = storage.Client(project=project)
        buckets = storage_client.list_buckets()

        for bucket in buckets:
            policy = bucket.get_iam_policy()

            for role in policy:
                members = policy[role]

                for member in members:
                    if member.startswith('user:') and domain not in member:
                        alert = True
                        logger.warning(' Bucket "{0}" in Project "{1}" contains non-organizational account "{2}"'.
                                       format(bucket.name, project, member))

    except Exception as err:
        logger.error('Error: {0}'.format(err))

if alert is False:
    logger.info('No non-organizational accounts found on buckets')
