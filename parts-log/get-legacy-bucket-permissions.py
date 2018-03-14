from google.cloud import storage
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects


# Logs Legacy Bucket Permissions

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()

bucket_dict = {}
bckts = []
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

logger.info('-----Checking for legacy bucket permissions-----')
for project in get_projects():
    storage_client = storage.Client(project=project)
    buckets = storage_client.list_buckets()

    try:
        for bucket in buckets:
            policy = bucket.get_iam_policy()
            for role in policy:
                members = policy[role]

                for member in members:
                    if role == 'roles/storage.legacyBucketOwner' or role == 'roles/storage.legacyBucketReader':
                        alert = True
                        logger.warning('"{0}" permission for member "{1}" applied to Bucket "{2}"'
                                       ' in project "{3}"'.format(role, member, bucket.name, project))
    except Exception as err:
        logger.info(err)

if alert is False:
    logger.info('No Legacy Bucket permissions found')
