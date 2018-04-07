from google.cloud import storage
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

import os
import logging
import smtplib
import credentials


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


def send_email(subject, body):
    """send email alert"""
    logger.info('Sending email')
    recipient = credentials.get_recipient_email()
    subject = subject

    # gmail sign-in
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
        logger.error('Gmail failure: {0}'.format(err))
        exit(1)

    body = '\r\n'.join(['To: %s' % recipient,
                        'From: %s' % gmail_sender,
                        'Subject: %s' % subject,
                        '', body])

    try:
        server.sendmail(gmail_sender, [recipient], body)
        logger.info('Email sent!')
    except Exception as err:
        logger.error('Sending mail failure: {0}'.format(err))

    server.quit()


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

subject_text = 'Globally Accessible Buckets Found and Fixed!'
body_text = ('Globally accessible permissions were removed on the following Buckets.  '
             'See logs for additional information.\n\n')
body_text += '\n'.join({'Bucket:\t{0}\nProject:\t{1}\n'.format(key, value) for (key, value) in bucket_dict.items()})

if alert:
    send_email(subject_text, body_text)
else:
    logger.info('No world readable permissions removed')
