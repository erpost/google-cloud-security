from google.cloud import storage
from googleapiclient import discovery
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects
import os
import logging

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()
bucket_dict = {}
bckts = []

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


def get_world_readable_buckets():
    """logs world-readable buckets with AllUsers or AllAuthenticatedUsers permissions"""
    alert = False
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
                        logger.warning('"{0}" permissions found applied to Bucket "{1}" in project "{2}"'.
                                       format(member, bucket.name, project_name))
    if alert is False:
        logger.info('No world-readable Bucket permissions found')

    return alert


def get_default_service_accounts():
    """logs Default Service Accounts found in IAM > Service Accounts"""
    alert = False
    for project in get_projects():
        project_name = 'projects/' + project
        service = discovery.build('iam', 'v1')
        request = service.projects().serviceAccounts().list(name=project_name)
        response = request.execute()

        try:
            accounts = response['accounts']

            for account in accounts:
                serviceaccount = account['email']

                if 'gserviceaccount.com' in serviceaccount and 'iam' not in serviceaccount:
                    alert = True
                    logger.warning('Default Service Account "{0}" found in project "{1}"'.
                                   format(serviceaccount, project))
        except:
            pass

    if alert is False:
        logger.info('No Default Service Accounts found')

    return alert


def get_default_vpc():
    """logs Default VPCs"""
    alert = False
    for project_name in get_projects():
        service = discovery.build('compute', 'v1')
        request = service.networks().list(project=project_name)
        response = request.execute()
        try:
            items = response['items']
            for item in items:
                vpc = item['name']

                if vpc == 'default':
                    alert = True
                    logger.warning('Default VPC Network "{0}" found in project "{1}"'.format(vpc, project_name))
        except:
            pass

    if alert is False:
        logger.info('No Default VPCs found')

    return alert


def send_email():
    pass


if __name__ == "__main__":

    world_buckets = get_world_readable_buckets()
    service_accounts = get_default_service_accounts()
    default_vpc = get_default_vpc()

    if world_buckets is True or\
       service_accounts is True or\
       default_vpc is True:
        send_email()
