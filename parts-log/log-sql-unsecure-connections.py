from googleapiclient import discovery
from googleapiclient.errors import HttpError
from pprint import pprint


try:
    service = discovery.build('sqladmin', 'v1beta4')
    request = service.instances().list(project='allofus-forseti')
    response = request.execute()
    items = response['items']
    # pprint(response)

    for item in items:
        ssl_enforced = item['settings']['ipConfiguration']['requireSsl']
        print(ssl_enforced)

except KeyError:
    print('Does not exist')

except HttpError as he:
    pprint(he.resp)
    if he.resp.status in [403, 500, 503]:
        print(he.resp.status)
