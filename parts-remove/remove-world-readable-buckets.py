from google.cloud import storage
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects


# Removes Global Permissions from Google Cloud Platform Buckets and sends Email with Bucket and Project Names

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

for project_name in get_projects():
    storage_client = storage.Client(project=project_name)
    buckets = storage_client.list_buckets()

    for bucket in buckets:
        policy = bucket.get_iam_policy()
        for role in policy:
            members = policy[role]

            for member in members:
                if member == 'allUsers' or member == 'allAuthenticatedUsers':
                    alert = True
                    logger.warning('"{0}" permissions were removed from Bucket "{1}" in project "{2}"'.
                                   format(member, bucket.name, project_name))
                    bucket_dict[bucket.name] = project_name
                    policy = bucket.get_iam_policy()
                    policy[role].discard(member)
                    bucket.set_iam_policy(policy)
if alert is False:
    logger.info('No world-readable Bucket permissions found')