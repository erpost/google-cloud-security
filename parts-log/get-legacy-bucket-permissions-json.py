from google.cloud import storage
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

import os
import logging
import logmatic

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
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(logfile, maxBytes=5*1024*1024, backupCount=5)
handler.setFormatter(logmatic.JsonFormatter())
logger.addHandler(handler)

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
                        logger.warning('{0} permission found'.format(role), extra={'rule': 'legacy bucket permissions',
                                                                                    'projectName': project,
                                                                                    'resourceType': 'gcs_bucket',
                                                                                    'resourceName': bucket.name})
                    else:
                        logger.info('no legacy permissions found'.format(role), extra={'rule': 'legacy bucket permissions',
                                                                                    'projectName': project,
                                                                                    'resourceType': 'gcs_bucket',
                                                                                    'resourceName': bucket.name})
    except Exception as err:
        logger.error(err, extra={'rule': 'legacy bucket permissions',
                                'projectName': project,
                                'resourceType': 'gcs_bucket'})

if alert is False:
    pass
