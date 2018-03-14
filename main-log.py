from google.cloud import storage
from googleapiclient import discovery
from logging.handlers import RotatingFileHandler
from tempfile import TemporaryFile
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
findings = TemporaryFile()

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
    world_bucket_total = []

    logger.info('-----Checking for world-readable bucket permissions-----')
    for project in get_projects():
        storage_client = storage.Client(project=project)
        buckets = storage_client.list_buckets()

        try:
            for bucket in buckets:
                policy = bucket.get_iam_policy()
                for role in policy:
                    members = policy[role]

                    for member in members:
                        if member == 'allUsers' or member == 'allAuthenticatedUsers':
                            alert = True
                            if bucket.name not in world_bucket_total:
                                world_bucket_total.append(bucket.name)
                            logger.warning('"{0}" permissions found applied to Bucket "{1}" in project "{2}"'.
                                           format(member, bucket.name, project))

        except Exception as err:
            logger.error(err)

    if alert is False:
        logger.info('No world-readable Bucket permissions found')

    data = '{0} buckets have world-readable permissions\n'.format(len(world_bucket_total))
    findings.write(bytes(data, 'UTF-8'))

    return alert


def get_default_service_accounts():
    """logs Default Service Accounts found in IAM > Service Accounts"""
    alert = False
    service_account_total = 0

    logger.info('-----Checking for default Service Accounts-----')
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
                    service_account_total += 1
                    logger.warning(' Default Service Account "{0}" found in project "{1}"'.
                                   format(serviceaccount, project))
        except KeyError:
            logger.info('No Service Accounts found in project "{0}"'.format(project))

        except Exception as err:
            logger.error(err)

    if alert is False:
        logger.info('No Default Service Accounts found')

    data = '{0} default service accounts\n'.format(service_account_total)
    findings.write(bytes(data, 'UTF-8'))

    return alert


def get_default_vpc():
    """logs Default VPCs"""
    alert = False

    logger.info('-----Checking for default VPCs-----')
    for project in get_projects():
        try:
            service = discovery.build('compute', 'v1')
            request = service.networks().list(project=project)
            response = request.execute()
            items = response['items']

            for item in items:
                vpc = item['name']
                autocreate = item['autoCreateSubnetworks']

                if vpc == 'default' and autocreate is True:
                    alert = True
                    logger.warning(' Default VPC Network "{0}" found in project "{1}"'.format(vpc, project))

        except KeyError:
            logger.info('No VPCs found in project "{0}"'.format(project))

        except Exception as err:
            logger.error(err)

    if alert is False:
        logger.info('No Default VPCs found')

    return alert


def get_non_us_vpc_subnets():
    """logs all non-US Subnets"""
    alert = False

    logger.info('-----Checking for non-US VPC subnets-----')
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
                            logger.warning('Non-US subnet "{0}" found in VPC "{1}" in project "{2}"'.
                                           format(subnet, vpc, project))

        except KeyError:
            logger.info('No VPCs found in project "{0}"'.format(project))

        except Exception as err:
            logger.error(err)

    if alert is False:
        logger.info(' No non-US subnets found')

    return alert


def get_service_account_keys():
    """logs all Service Accounts Keys that are older than 180 days"""
    alert = False

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

    return alert


def get_legacy_bucket_permissions():
    """logs all buckets containing legacy permissions"""
    alert = False

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

    return alert


def get_user_accounts():
    """logs User Accounts not part of the specified GCP Organization"""
    alert = False

    logger.info('-----Checking for non-organizational accounts in IAM-----')
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
                            logger.warning(' Project "{0}" contains non-organizational account "{1}"'.
                                           format(project, member))
                            user_list.append(member)
                        else:
                            pass

        except KeyError as err:
            logger.info('No User Accounts found in project "{0}": {1}'.format(project, err))

        except Exception as err:
            logger.error(err)

    if alert is False:
        logger.info('No non-organizational users found')

    return alert


def get_user_accounts_buckets():
    """logs User Accounts tied to GCP Buckets that are not part of the specified GCP Organization"""
    alert = False
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

    return alert


def get_sql_unsecure_connections():
    """logs all Cloud SQL Databases without enforced SSL Connections"""
    alert = False

    logger.info('-----Checking for SQL unsecure connections-----')
    for project in get_projects():
        try:
            service = discovery.build('sqladmin', 'v1beta4')
            request = service.instances().list(project=project)
            response = request.execute()

            if 'items' in response:
                items = response['items']
                for item in items:
                    db_name = item['name']
                    if 'requireSsl' not in item['settings']['ipConfiguration']:
                        logger.warning('Database "{0}" in Project "{1}" does not have SSL enforced'.
                                       format(db_name, project))
                        alert = True
                    else:
                        ssl = item['settings']['ipConfiguration']['requireSsl']
                        logger.info('Database "{0}" in Project "{1}" SSL is set to: "{2}".'.
                                    format(db_name, project, ssl))

            else:
                logger.info('0 Databases in Project "{0}"'.format(project))

        except Exception as err:
            logger.error(err)

    if alert is False:
        logger.info(' No Cloud SQL found without SSL Connections enforced')

    return alert


def send_email():
    """send email alert"""
    logger.info('Sending email')
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
        logger.error('Bad credentials.  Exiting...')
        exit(1)
    except Exception as err:
        logger.error('Gmail error: '.format(err))
        exit(1)

    body = '\r\n'.join(['To: %s' % recipient,
                        'From: %s' % gmail_sender,
                        'Subject: %s' % subject,
                        '', body])

    try:
        server.sendmail(gmail_sender, [recipient], body)
        logger.info('Email sent')
    except Exception as err:
        logger.error('Error sending mail: '.format(err))

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
    sql_unsecure_connections = get_sql_unsecure_connections()

    if world_buckets is True or\
        service_accounts is True or\
        service_keys is True or\
        default_vpc is True or\
        non_us_subnets is True or\
        legacy_buckets is True or\
        user_accounts is True or\
        user_account_buckets is True or \
        sql_unsecure_connections is True:
        send_email()
        findings.seek(0)
        print(findings.read().decode())
