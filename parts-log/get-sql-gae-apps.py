from googleapiclient import discovery
import os
import logging
from logging.handlers import RotatingFileHandler
from gcp import get_key, get_projects

from pprint import pprint


# Logs all Cloud SQL Databases with Authorized Networks

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()

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


def get_sql_gae_apps():
    """logs all Cloud SQL Database Users"""
    alert = False
    sql_users_total = 0
    sql_users_errors = 0

    logger.info('-----Checking for SQL unsecure connections-----')
    for project in get_projects():
        try:
            service = discovery.build('sqladmin', 'v1beta4')
            request = service.instances().list(project=project)
            response = request.execute()

            if 'items' in response:
                items = response['items']
                for item in items:
                    # pprint(item)
                    print(item['name'])
                    print(item['settings']['authorizedGaeApplications'])
                    print(item['settings']['dataDiskSizeGb'])
                    # db_name = item['name']
            #         auth_nets = item['settings']['ipConfiguration']['authorizedNetworks']
            #         if auth_nets:
            #             alert = True
            #             sql_auth_networks_total += 1
            #             for auth_net in auth_nets:
            #                 nets = auth_net['value']
            #                 logger.warning('Database "{0}" in Project "{1}" has Authorized Networks: {2}'.
            #                                format(db_name, project, nets))
            #             alert = True
            #         else:
            #             logger.info('Database "{0}" in Project "{1}" has no Authorized Networks'.
            #                         format(db_name, project))
            #
            # else:
            #     logger.info('0 Databases in Project "{0}"'.format(project))

        except Exception as err:
            sql_users_errors += 1
            logger.error(err)
    #
    # if alert is False:
    #     logger.info('No Cloud SQL Authorized Networks found')

    # write to tempfile
    # term = 'Cloud SQL Databases with Authorized Networks'
    # data = '{}\n- {:>4} Violation(s)\n- {:>4} Error(s)\n\n'.format(term, sql_users_total,
    #                                                                sql_users_errors)
    # findings.write(bytes(data, 'UTF-8'))

    return alert


if __name__ == "__main__":
    get_sql_gae_apps()