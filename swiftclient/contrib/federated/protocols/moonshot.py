# Created on 8 March 2013
# @author: Vincent Giersch

import copy
import json
import urllib3
import logging
import pymoonshot as moonshot
from swiftclient.contrib.federated import federated_exceptions, federated_utils

LOG = logging.getLogger('swiftclient')
LOG.addHandler(logging.StreamHandler())
LOG.setLevel(logging.INFO)


class MoonshotException(Exception):
    pass


class MoonshotNegotiation(object):
    def __init__(self, keystoneEndpoint, serviceName, mechanism,
                 requestPool, protocol, protocol_id):
        self.protocol = protocol
        self.protocol_id = protocol_id
        self.context = None
        self.serviceName = serviceName
        self.mechanism = mechanism
        self.cid = None

        self.requestPool = requestPool
        self.keystoneEndpoint = keystoneEndpoint
        self.strNegotiation = ''

    def negotiation(self):
        gss_flags = moonshot.GSS_C_MUTUAL_FLAG | moonshot.GSS_C_INTEG_FLAG | \
            moonshot.GSS_C_SEQUENCE_FLAG | moonshot.GSS_C_REPLAY_FLAG | \
            moonshot.GSS_C_CONF_FLAG
        result, self.context = moonshot.authGSSClientInit(
            self.serviceName,
            gss_flags,
            self.mechanism)
            #moonshot.GSS_SPNEGO)

        if result != 1:
            raise MoonshotException(
                'moonshot.authGSSServerInit returned result %d' % result
            )

        strNegotiation = moonshot.AUTH_GSS_CONTINUE
        while strNegotiation != moonshot.AUTH_GSS_COMPLETE:
            strNegotiation = self.negotiationStep()

        LOG.info(
            '\nAuthentication successful using \'%s\' moonshot identity.\n',
            moonshot.authGSSClientUserName(self.context)
        )

        return self.cid

    def negotiationStep(self):
        LOG.debug('response: %r' % self.strNegotiation)
        result = moonshot.authGSSClientStep(self.context, self.strNegotiation)

        # Build request using GSS challenge
        strNegotiation = moonshot.authGSSClientResponse(self.context)

        # Send request only if the challenge is not empty (end of negotiation)
        if strNegotiation is not None:
            response = self.negotiationRequest(strNegotiation)
            if 'error' in response and 'identity' in response['error']:
                response = response['error']['identity']['federated']
            self.cid = response['cid']
            self.strNegotiation = response['negotiation']
            LOG.debug('response: %r', json.dumps(self.strNegotiation))
        LOG.debug('authGSSClientStep: %d', result)
        return result

    def negotiationRequest(self, body):
        headers = {'Content-Type': 'application/json'}
        body = json.dumps({
            'auth': {
                'identity': {
                    'methods': ['federated'],
                    'federated': {
                        'protocol': self.protocol,
                        'provider_id': self.protocol_id,
                        'phase': 'negotiate',
                        'cid': self.cid,
                        'negotiation': body
                    }
                }
            }
        })

        LOG.debug('request: %s', body)
        return json.loads(self.requestPool.urlopen(
            'POST', self.keystoneEndpoint + 'auth/tokens',
            body=body, headers=headers
        ).data)


## Sends the authentication request to the IdP along
def getIdPResponse(
    keystoneEndpoint, moonshotDetail, requestPool,
    protocol=None, protocol_id=None
):
    m = MoonshotNegotiation(
        keystoneEndpoint,
        moonshotDetail['serviceName'], moonshotDetail['mechanism'],
        requestPool, protocol, protocol_id
    )
    return m.negotiation()
