from logging.handlers import RotatingFileHandler

import logging
import os
import credentials
import smtplib

# set logging path
path = os.path.expanduser('~/python-logs')
logfile = os.path.expanduser('~/python-logs/security.log')

logger = logging.getLogger("Rotating Log")
log_formatter = logging.Formatter('%(asctime)s\t %(levelname)s %(message)s')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(logfile, maxBytes=5*1024*1024, backupCount=5)
handler.setFormatter(log_formatter)
logger.addHandler(handler)


def send_gmail(subject, body):
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


if __name__ == "__main__":
    subject = 'Test Email'
    body = 'This email is a test'
    send_gmail(subject, body)
