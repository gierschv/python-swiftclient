import json
import urllib
import urllib3


## Send a request that will be process by the Federation Middleware
def middlewareRequest(
    keystoneEndpoint, data={}, method='GET',
    pool=None, headers={}
):
    #print 'Request: %r' % json.dumps(data)
    # headers = {'X-Authentication-Type': 'federated'}
    if pool is None:
        pool = urllib3.PoolManager()

    if method == 'GET':
        data = urllib.urlencode(data)
        response = pool.request(
            'GET', keystoneEndpoint, fields=data, headers=headers
        )
    elif method == 'POST':
        data = json.dumps(data)
        headers['Content-Type'] = 'application/json'
        response = pool.urlopen(
            'POST', keystoneEndpoint, body=data, headers=headers
        )

    return response


## Displays the list of tenants to the user so he can choose one
def selectTenant(tenantsList, serverName=None):
    if not serverName:
        print 'You have access to the following tenant(s):'
    else:
        print 'You have access to the following tenant(s) on '+serverName+':'
    for idx, tenant in enumerate(tenantsList):
        print '\t{', idx, '} ', tenant['project']['description']
    chosen = False
    choice = None
    while not chosen:
        try:
            choice = int(raw_input(
                'Enter the number corresponding to the tenant you want to use:'
            ))
        except:
            print 'An error occurred with your selection'
        if not choice is None:
            if choice < 0 or choice >= len(tenantsList):
                chosen = False
            print 'The selection made was not a valid choice of tenant'
        else:
            chosen = True
    return tenantsList[choice]


## Displays the list of realm to the user
def selectProvider(providerList):
    print 'Please use one of the following services to authenticate you:'
    print providerList
    for idx, provider in enumerate(providerList):
        print '\t{', idx, '} ', provider['service']['name']
    choice = None
    while choice is None:
        try:
            choice = int(raw_input(
                'Enter the number corresponding to the service you want to use:'
            ))
        except:
            print 'An error occurred with your selection'
        if choice < 0 or choice >= len(providerList):
            print 'The selection made was not a valid choice of service'
        choice = None
    return providerList[choice]['service']


## Given a tenants list and a friendly name, returns the corresponding tenantId
def getTenantId(tenantsList, friendlyname):
    for idx, tenant in enumerate(tenantsList):
        if tenant['project']['name'] == friendlyname:
            return tenant['project']['id']
