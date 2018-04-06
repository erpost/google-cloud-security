from google.cloud import storage
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects, send_gmail

import os
import logging


"""Removes Global Permissions from Google Cloud Platform Buckets and sends Email with Bucket and Project Names"""

alert = False
bucket_dict = {}
bckts = []

# set GCP key
if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()

# set logging path
path = os.path.expanduser('~/python-logs')
logfile = os.path.expanduser('~/python-logs/security.log')

if os.path.isdir(path):
    pass
else:
    os.mkdir(path)

# setup logging
logger = logging.getLogger("Rotating Log")
log_formatter = logging.Formatter('%(asctime)s\t %(levelname)s %(message)s')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(logfile, maxBytes=5*1024*1024, backupCount=5)
handler.setFormatter(log_formatter)
logger.addHandler(handler)


for project_name in get_projects():
    storage_client = storage.Client(project=project_name)
    buckets = storage_client.list_buckets()

    try:
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
    except Exception as err:
        logger.error(err)

subject = 'Globally Accessible Buckets Found and Fixed!'
body_text = ('Globally accessible permissions were removed on the following Buckets.  '
             'See logs for additional information.\n\n')
body_text += '\n'.join({'Bucket:\t{0}\nProject:\t{1}\n'.format(key, value) for (key, value) in bucket_dict.items()})

if alert:
    send_gmail(subject, body_text)
else:
    logger.info('No world readable permissions removed')
