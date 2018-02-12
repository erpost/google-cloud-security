from google.cloud import storage
from googleapiclient import discovery
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects
from datetime import datetime
from dateutil.relativedelta import relativedelta
import os
import logging


if os.path.isfile(get_key()):
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


def get_service_account_keys():
    """logs all Service Accounts Keys that are older than 90 days"""
    alert = False

    for project in get_projects():
        project_name = 'projects/' + project
        service = discovery.build('iam', 'v1')
        request = service.projects().serviceAccounts().list(name=project_name)
        response = request.execute()

        try:
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

                    if key_age_years > 0:
                        key_age_days = relativedelta(datetime.utcnow(), startdate).days
                        if key_age_days > 90:
                            alert = True
                            logger.warning('Service Account key is older than 90 days: {0}'.format(keyname))
        except KeyError:
            pass

    if alert is False:
        logger.info('No Service Account Keys older than 90 days found')

    return alert


def send_email():
    pass


if __name__ == "__main__":

    world_buckets = get_world_readable_buckets()
    service_accounts = get_default_service_accounts()
    default_vpc = get_default_vpc()
    service_keys = get_service_account_keys()

    if world_buckets is True or\
        service_accounts is True or\
        service_keys is True or\
        default_vpc is True:
        send_email()
