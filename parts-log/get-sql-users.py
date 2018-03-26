from googleapiclient import discovery
from tempfile import TemporaryFile
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

import os
import logging

from pprint import pprint


# Logs all Cloud SQL Databases with Authorized Networks

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()

findings = TemporaryFile()
opener = 'Hello, \n\nBelow are the high-level findings for Google Cloud. ' \
         'Check logs for specific findings and errors.\n\n\n'
findings.write(bytes(opener, 'UTF-8'))

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


def get_sql_users():
    """logs all Cloud SQL Database Users"""
    alert = False
    # sql_version_total = 0
    # sql_version_errors = 0

    # logger.info('-----Checking SQL versions-----')
    # for project in get_projects():
    #     try:
    project = 'allofus-forseti'
    instance = 'first-gen'
    service = discovery.build('sqladmin', 'v1beta4')
    request = service.users().list(project=project, instance=instance)
    response = request.execute()
    pprint(response)

        # if 'items' in response:
        #     items = response['items']
        #     for item in items:
        #         # db_name = item['name']
        #         print(item)

            #             alert = True
            #             sql_version_total += 1
            #             logger.warning('Database "{0}" in Project "{1}" is version: {2}'.
            #                            format(db_name, project, db_ver))
            #             alert = True
            #         else:
            #             logger.info('Database "{0}" in Project "{1}" is version: {2}'.
            #                         format(db_name, project, db_ver))
            #
            # else:
            #     logger.info('0 Databases in Project "{0}"'.format(project))

        # except Exception as err:
        #     sql_version_errors += 1
        #     logger.error(err)

    # if alert is False:
    #     logger.info('No non-2nd Generation Cloud SQL Versions found')
    #
    # # write to tempfile
    # term = 'Cloud SQL Versions not equal to 2nd Generation:'
    # data = '{}\n- {:>4} Violation(s)\n- {:>4} Error(s)\n\n'.format(term, sql_version_total, sql_version_errors)
    # findings.write(bytes(data, 'UTF-8'))

    return alert


if __name__ == "__main__":
    get_sql_users()
    # findings.seek(0)
    # print(findings.read().decode())
    # findings.close()
