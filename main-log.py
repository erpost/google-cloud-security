from google.cloud import storage
from googleapiclient import discovery
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects
from datetime import datetime
from dateutil.relativedelta import relativedelta

import os
import smtplib
import re
import logging
import credentials


domain = credentials.get_org_domain()

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()

bucket_dict = {}
bckts = []

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
                        logger.warning('| "{0}" permissions found applied to Bucket "{1}" in project "{2}"'.
                                       format(member, bucket.name, project_name))
    if alert is False:
        logger.info('| No world-readable Bucket permissions found')

    return alert


def get_default_service_accounts():
    """logs Default Service Accounts found in IAM > Service Accounts"""
    alert = False
    for project in get_projects():
        project_name = 'projects/' + project
        try:
            service = discovery.build('iam', 'v1')
            request = service.projects().serviceAccounts().list(name=project_name)
            response = request.execute()
            accounts = response['accounts']

            for account in accounts:
                serviceaccount = account['email']

                if 'gserviceaccount.com' in serviceaccount and 'iam' not in serviceaccount:
                    alert = True
                    logger.warning('| Default Service Account "{0}" found in project "{1}"'.
                                   format(serviceaccount, project))
        except KeyError:
            logger.info('| 0 Service Accounts found in project "{0}"'.format(project))

        except Exception:
            logger.error('| Default Service Account - Unknown error.  Please run manually')

    if alert is False:
        logger.info('| No Default Service Accounts found')

    return alert


def get_default_vpc():
    """logs Default VPCs"""
    alert = False
    for project_name in get_projects():
        try:
            service = discovery.build('compute', 'v1')
            request = service.networks().list(project=project_name)
            response = request.execute()
            items = response['items']

            for item in items:
                vpc = item['name']
                autocreate = item['autoCreateSubnetworks']

                if vpc == 'default' and autocreate is True:
                    alert = True
                    logger.warning('| Default VPC Network "{0}" found in project "{1}"'.format(vpc, project_name))

        except KeyError:
            logger.info('| 0 VPCs found in project "{0}"'.format(project_name))

        except Exception:
            logger.error('| Default VPC Network - Unknown error in project "{0}".  Please run manually'.format(project_name))

    if alert is False:
        logger.info('| No Default VPCs found')

    return alert


def get_non_us_vpc_subnets():
    """logs all non-US Subnets"""
    alert = False
    for project in get_projects():
        try:
            service = discovery.build('compute', 'v1')
            request = service.networks().list(project=project)
            response = request.execute()
            items = response['items']

            for item in items:
                vpc = item['name']
                subnetworks = item['subnetworks']

                for subnetwork in subnetworks:
                    subnets = re.findall('regions/(.*)/subnetworks', subnetwork)

                    for subnet in subnets:
                        if 'us-' not in subnet:
                            alert = True
                            logger.warning(
                                '| Non-US subnet "{0}" found in VPC "{1}" in project "{2}"'.format(subnet, vpc,
                                                                                                   project))

        except KeyError:
            logger.info('| 0 VPCs found in project "{0}"'.format(project))

        except Exception:
            logger.error('| Non-US subnets - Unknown error.  Please run manually')

    if alert is False:
        logger.info('| No non-US subnets found')

    return alert


def get_service_account_keys():
    """logs all Service Accounts Keys that are older than 180 days"""
    alert = False

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

                    if key_age_years > 0:
                        key_age_days = relativedelta(datetime.utcnow(), startdate).days
                        if key_age_days > 90:
                            alert = True
                            logger.warning('| Service Account key is older than 180 days: {0}'.format(keyname))

        except KeyError:
            logger.info('| 0 Service Account keys found in project "{0}"'.format(project))

        except Exception:
            logger.error('| Service Account key - Unknown error.  Please run manually')

    if alert is False:
        logger.info('| No Service Account Keys older than 180 days found')

    return alert


def get_legacy_bucket_permissions():
    """logs all buckets containing legacy permissions"""
    alert = False
    for project_name in get_projects():
        storage_client = storage.Client(project=project_name)
        buckets = storage_client.list_buckets()

        for bucket in buckets:
            policy = bucket.get_iam_policy()
            for role in policy:
                members = policy[role]

                for member in members:
                    if role == 'roles/storage.legacyBucketOwner' or role == 'roles/storage.legacyBucketReader':
                        alert = True
                        logger.warning('| "{0}" permission for member "{1}" applied to Bucket "{2}"'
                                       ' in project "{3}"'.format(role, member, bucket.name, project_name))

    if alert is False:
        logger.info('| No Legacy Bucket permissions found')

    return alert


def get_user_accounts():
    """logs User Accounts not part of the specified GCP Organization"""
    alert = False
    for project in get_projects():
        user_list = []
        try:
            service = discovery.build('cloudresourcemanager', 'v1')
            request = service.projects().getIamPolicy(resource=project, body={})
            response = request.execute()
            bindings = response['bindings']

            for binding in bindings:
                for member in binding['members']:
                    if member.startswith('user:') and domain not in member:
                        alert = True
                        if member not in user_list:
                            logger.warning('| Project "{0}" contains non-organizational account "{1}"'.format(project,
                                                                                                              member))
                            user_list.append(member)
                        else:
                            pass

        except KeyError:
            logger.info('| 0 User Accounts found in project "{0}"'.format(project))

        except Exception:
            logger.error('| Non-Organizational User Accounts - Unknown error.  Please run manually')

    if alert is False:
        logger.info('| No non-organizational users found')

    return alert


def get_user_accounts_buckets():
    """logs User Accounts tied to GCP Buckets that are not part of the specified GCP Organization"""
    alert = False

    for project_name in get_projects():
        storage_client = storage.Client(project=project_name)
        buckets = storage_client.list_buckets()

        for bucket in buckets:
            policy = bucket.get_iam_policy()

            for role in policy:
                members = policy[role]

                for member in members:
                    if member.startswith('user:') and domain not in member:
                        alert = True
                        logger.warning('| Bucket "{0}" in Project "{1}" contains non-organizational account "{2}"'.
                                       format(bucket.name, project_name, member))

    if alert is False:
        logger.info('| No non-organizational accounts found on buckets')

    return alert


def send_email():
    """send email alert"""
    logger.info('| Sending email')
    recipient = credentials.get_recipient_email()
    subject = 'Google Cloud Security Risks Found!'
    body = 'Please log into your Google Account and review Security Logs.\n\n\nThank you,\nSecurity'

    # Gmail Sign In
    gmail_sender = credentials.get_sender_email()
    gmail_passwd = credentials.get_password()
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo()
        server.starttls()
        server.login(gmail_sender, gmail_passwd)
    except smtplib.SMTPAuthenticationError:
        logger.error('| Bad credentials.  Exiting...')
        exit(1)
    except Exception:
        logger.error('| Gmail unknown error.  Exiting...')
        exit(1)

    body = '\r\n'.join(['To: %s' % recipient,
                        'From: %s' % gmail_sender,
                        'Subject: %s' % subject,
                        '', body])

    try:
        server.sendmail(gmail_sender, [recipient], body)
        logger.info('| Email sent')
    except Exception:
        logger.error('| Error sending mail')

    server.quit()


if __name__ == "__main__":

    world_buckets = get_world_readable_buckets()
    service_accounts = get_default_service_accounts()
    default_vpc = get_default_vpc()
    non_us_subnets = get_non_us_vpc_subnets()
    service_keys = get_service_account_keys()
    legacy_buckets = get_legacy_bucket_permissions()
    user_accounts = get_user_accounts()
    user_account_buckets = get_user_accounts_buckets()

    if world_buckets is True or\
        service_accounts is True or\
        service_keys is True or\
        default_vpc is True or\
        non_us_subnets is True or\
        legacy_buckets is True or\
        user_accounts is True or\
        user_account_buckets is True:
        send_email()
