import imp
import os
import json
import urllib3
import federated_utils as futils


## The super-function calls different API methods to obtain the scoped token
# @param keystoneEndpoint The keystone url
# @param realm The IdP the user will be using
# @param tenantFn The tenant friendly name the user wants to use
def federatedAuthentication(keystoneEndpoint, realm=None, tenantFn=None):
    # Get federated protocol
    providers = discoverServices(keystoneEndpoint)
    provider = futils.selectProvider(providers)

    # Request issuing
    request = requestIssuing(
        keystoneEndpoint, provider['name'], provider['id']
    )
    processing_module = load_protocol_module(provider['name'])

    # Call protocol: negotiation ...
    requestPool = urllib3.PoolManager()
    cid = processing_module.getIdPResponse(
        keystoneEndpoint, request,
        requestPool, provider['name'], provider['id']
    )

    # Validation
    unscopedDetails, unscopedToken = getUnscopedToken(
        keystoneEndpoint, cid, provider['name'], provider['id']
    )

    # User projects
    projects = getUserProject(
        keystoneEndpoint, unscopedDetails['token']['user']['id'], unscopedToken
    )

    # TODO

    # tenantData = getUnscopedToken(
    #    keystoneEndpoint, response, requestPool, realm
    #)
    # tenant = futils.getTenantId(tenantData['tenants'], tenantFn)
    # if tenant is None:
    #     tenant = futils.selectTenant(tenantData['tenants'])['project']['id']
    # scopedToken = swapTokens(
    #    keystoneEndpoint, tenantData['unscopedToken'], tenant
    #)

    return scopedToken


def load_protocol_module(protocol):
    # Dynamically load correct module for processing authentication
    # according to identity provider's protocol
    return imp.load_source(
        protocol, os.path.dirname(__file__) + '/protocols/' + protocol + '.py'
    )


## Discover the federated authentication service available
# @param keystoneEndpoint The keystone url
def discoverServices(keystoneEndpoint):
    data = {
        'auth': {
            'identity': {
                'methods': ['federated'],
                'federated': {
                    'phase': 'discovery'
                }
            }
        }
    }

    resp = futils.middlewareRequest(
        keystoneEndpoint + 'auth/tokens', data, 'POST'
    )

    return json.loads(resp.data)['error']['identity']['federated']['providers']


## Request issuing service
# @param keystoneEndpoint The keystone url
def requestIssuing(keystoneEndpoint, protocol, protocol_id):
    data = {
        'auth': {
            'identity': {
                'methods': ['federated'],
                'federated': {
                    'protocol': protocol,
                    'provider_id': protocol_id,
                    'phase': 'request'
                }
            }
        }
    }

    resp = futils.middlewareRequest(
        keystoneEndpoint + 'auth/tokens', data, 'POST'
    )
    return json.loads(resp.data)['error']['identity']['federated']


## Get the unscoped token
# @param keystoneEndpoint The keystone url
# @param cid: The client id
# @param protocol: The used protocol
# @param protocol_id: The used protocol identifier
# @param assertion
def getUnscopedToken(
    keystoneEndpoint, cid, protocol,
    protocol_id, assertion=None
):
    data = {
        'auth': {
            'identity': {
                'methods': ['federated'],
                'federated': {
                    'protocol': protocol,
                    'provider_id': protocol_id,
                    'phase': 'validate',
                    'assertion': assertion,
                    'cid': cid
                }
            }
        }
    }

    resp = futils.middlewareRequest(
        keystoneEndpoint + 'auth/tokens', data, 'POST'
    )

    return json.loads(resp.data), resp.headers['x-subject-token']


## Get the user projects
def getUserProject(keystoneEndpoint, user, unscopedToken):
    resp = futils.middlewareRequest(
        #keystoneEndpoint + 'users/' + urllib.quote(user, '') + '/projects'
        keystoneEndpoint + 'users/' + user + '/projects',
        headers={'X-Auth-Token': unscopedToken}
    )
    return json.loads(resp.data)
