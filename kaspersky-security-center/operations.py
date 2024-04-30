"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""
import base64, json, requests

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('kaspersky-security-center')

errors = {
    400: 'Invalid Argument/Invalid Time Range',
    404: 'Method Not Allowed',
    429: 'OperationLockoutError',
    500: 'Database Unavilable',
    503: 'Maximum Requests Exceeded'
}


class KasperskyEDR(object):
    def __init__(self, config, *args, **kwargs):
        url = config.get('server_url').strip('/') + ':' + str(config.get('server_port'))
        if not url.startswith('https://') and not url.startswith('http://'):
            self.server_url = 'https://{0}/'.format(url)
        else:
            self.server_url = url + '/'
        self.username = config.get('username')
        self.password = config.get('password')
        self.sslVerify = config.get('verify_ssl')
        self.Session()

    def make_request(self, endpoint, headers=None, params=None, data=None, method='GET'):
        try:
            url = self.server_url + endpoint
            logger.debug('Request data: {0}'.format(data))
            logger.debug('Request params : {0}'.format(params))
            response = requests.request(method, url, headers=headers, verify=self.sslVerify, data=data, params=params)
            if response.ok or response.status_code == 200:
                logger.debug('Successfully got response for url {0}'.format(url))
                logger.debug('Response body: {0}'.format(response.text))
                return response.json()
            else:
                if response.status_code == 403:
                    raise ConnectorError('Insufficient permission')
                else:
                    logger.error(response.text)
                    raise ConnectorError("{0}".format(errors.get(response.status_code, '')))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def Session(self):
        session = requests.Session()
        return session

    def start_session(self, config, params):
        user = base64.b64encode(config.get('username').encode('utf-8')).decode("utf-8")
        password = base64.b64encode(config.get('password').encode('utf-8')).decode("utf-8")
        headers = {'Content-Type': 'application/json',
                   'Authorization': 'KSCBasic user="{0}", pass="{1}", internal="0"'.format(user, password)
                   }
        endpoint = 'api/v1.0/Session.StartSession'

        token = self.make_request(endpoint=endpoint, method='POST', headers=headers)
        return {'X-KSC-Session': token['PxgRetVal'], 'Content-Type': 'application/json'}


def get_search_results(strAccessor, config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.1/ChunkAccessor.GetItemsCount'
    data = {"strAccessor": strAccessor}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    items_count = json.loads(response.text)['PxgRetVal']


def get_hosts_group_static_info(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/HostGroup.GetStaticInfo'
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, verify=False)
    return json.loads(response.text)


def get_host_details(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    host_id = params.get('host_id')
    endpoint = 'api/v1.0/HostGroup.GetHostInfo'
    data = {"strHostName": host_id,
            "pFields2Return": ['KLHST_WKS_OS_NAME', 'KLHST_WKS_LAST_FULLSCAN', 'KLHST_WKS_VIRUS_COUNT',
                               'KLHST_WKS_HOSTNAME', 'KLHST_WKS_DN', 'KLHST_WKS_DNSDOMAIN']}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def get_result(strAccessor, items_count, config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/ChunkAccessor.GetItemsChunk'
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    data = {
        "strAccessor": strAccessor,
        "nStart": 0,
        "nCount": items_count
    }
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    results = json.loads(response.text)['pChunk']['KLCSP_ITERATOR_ARRAY']
    return results


def get_groups(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/HostGroup.FindGroups'
    data = {"wstrFilter": "", "vecFieldsToReturn": ['id', 'name'], "lMaxLifeTime": 3600}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    strAccessor = json.loads(response.text)['strAccessor']
    items_count = get_search_results(strAccessor, config, params)
    items_count = json.loads(response.text)['PxgRetVal']
    response = get_result(strAccessor, items_count, config, params)
    return response


def get_listhost_group(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/HostGroup.FindHosts'
    group_id = params.get('group_id')
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    data = {"wstrFilter": "(KLHST_WKS_GROUPID = " + str(group_id) + ")",
            "vecFieldsToReturn": ['KLHST_WKS_FQDN',
                                  'KLHST_WKS_HOSTNAME', 'KLHST_WKS_DN', 'KLHST_WKS_OS_NAME'],
            "lMaxLifeTime": 3600}
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    strAccessor = json.loads(response.text)['strAccessor']
    items_count = get_search_results(strAccessor, config, params)
    items_count = json.loads(response.text)['PxgRetVal']
    response = get_result(strAccessor, items_count, config, params)
    return response


def delete_group(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'api/v1.0/HostGroup.RemoveGroup'
    data = {'nGroup': params.get('group_id'), 'nFlags': params.get('flag')}
    headers = kedr.start_session(config, params)
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def add_group(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/HostGroup.AddGroup'
    session = kedr.Session()
    data = {'pInfo': {'name': params.get('name'), 'parentId': params.get('parent_id')}}
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def get_software_installed(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/InventoryApi.GetHostInvProducts'
    data = {'szwHostId': str(params.get('host_id'))}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def get_product_installed(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/HostGroup.GetHostProducts'
    data = {"strHostName": str(params.get('host_id'))}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def list_policies_request(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/Policy.GetPoliciesForGroup'
    data = {"nGroupId": params.get('group_id')}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def get_policy_request(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/Policy.GetPolicyData'
    data = {"nPolicy": params.get('policy_id')}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def add_policy_request(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/Policy.AddPolicy'
    data = {'pPolicyData': {'KLPOL_DN': params.get('KLPOL_DN'),
                            'KLPOL_PRODUCT': params.get('KLPOL_PRODUCT'),
                            'KLPOL_VERSION': params.get('KLPOL_VERSION'),
                            'KLPOL_GROUP_ID': params.get('KLPOL_GROUP_ID')}}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def move_hosts(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/HostGroup.MoveHostsToGroup'
    pHostNames = [params.get('pHostNames')]
    data = {'nGroup': params.get('newgroup'), 'pHostNames': pHostNames}
    session = kedr.Session()
    url = "https://" + config.get('server_url') + ':' + str(config.get('server_port')) + '/' + endpoint
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return json.loads(response.text)


def _check_health(config):
    try:
        res = get_groups(config, params={})
        if res:
            return True
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'move_hosts': move_hosts,
    'add_policy_request': add_policy_request,
    'get_policy_request': get_policy_request,
    'list_policies_request': list_policies_request,
    'get_hosts_group_static_info': get_hosts_group_static_info,
    'get_host_details': get_host_details,
    'get_groups': get_groups,
    'get_listhost_group': get_listhost_group,
    'get_product_installed': get_product_installed,
    'delete_group': delete_group,
    'add_group': add_group,
    'get_software_installed': get_software_installed
}
