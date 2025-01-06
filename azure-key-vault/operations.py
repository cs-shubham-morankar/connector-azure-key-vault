"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""
import json
import requests
from connectors.core.connector import get_logger, ConnectorError
from .microsoft_api_auth import MicrosoftAuth
from .constants import *
from connectors.core.utils import update_connnector_config

logger = get_logger('azure-key-vault')


class AzureKeyVault(object):
    def __init__(self, config):
        self.server_url = 'https://'
        self.subscription_id = config.get('subscription_id')
        self.manage_server_url = MANAGE_SERVER_URL + '/{0}'.format(self.subscription_id)
        self.verify_ssl = config.get('verify_ssl')
        self.ms_auth = MicrosoftAuth(config)
        self.tenant_id = config.get('tenant_id')
        self.connector_info = config.pop('connector_info', '')
        self.manage_token = self.ms_auth.validate_token(config, self.connector_info)
        self.vault_token = self.ms_auth.validate_vault_token(config, self.connector_info)
        self.api_version = MANAGE_API_VERSION

    def make_rest_call(self, endpoint, params={}, data=None, method='POST', manage_api_endpoint=False):
        if manage_api_endpoint:
            headers = {
                'Authorization': self.manage_token,
                'Content-Type': 'application/json'
            }
            service_url = self.manage_server_url + endpoint
            params['api-version'] = MANAGE_API_VERSION
        else:
            headers = {
                'Authorization': self.vault_token,
                'Content-Type': 'application/json'
            }
            service_url = self.server_url + endpoint
            params['api-version'] = VAULT_API_VERSION
        logger.debug('Request URL {0}'.format(service_url))
        try:
            if data:
                data = json.dumps(data)
            response = requests.request(method, service_url, data=data, headers=headers, params=params,
                                        verify=self.verify_ssl)
            if response.ok:
                content_type = response.headers.get('Content-Type')
                if response.text != "" and 'application/json' in content_type:
                    return response.json()
                elif response.content:
                    return response.content
                else:
                    return response
            else:
                if response.text != "":
                    err_resp = json.loads(response.json()) if type(response.json()) is str else response.json()
                    if "error" in err_resp:
                        error_msg = "{}: {}".format(err_resp.get('error').get('code'),
                                                    err_resp.get('error').get('message'))
                        raise ConnectorError(error_msg)
                else:
                    error_msg = '{0}: {1}'.format(response.status_code, response.reason)
                    raise ConnectorError(error_msg)
        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred.')
            raise ConnectorError('A connection error occurred.')
        except requests.exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except requests.exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def list_key_vault(config, params):
    kv = AzureKeyVault(config)
    skip_token = params.get('skip_token')
    endpoint = '/resources?$skiptoken={0}'.format(skip_token) if skip_token else '/resources'
    payload = {
        "$filter": "resourceType eq 'Microsoft.KeyVault/vaults'"
    }
    size = params.get('size')
    if size:
        payload["$top"] = size
    response = kv.make_rest_call(endpoint=endpoint, params=payload, method='GET', manage_api_endpoint=True)
    return response


def get_key_vault(config, params):
    kv = AzureKeyVault(config)
    subscription_id = kv.subscription_id
    resource_group = params.get('resource_group_name')
    vault_name = params.get('vault_name')
    endpoint = '/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults/{2}'
    endpoint = endpoint.format(subscription_id, resource_group, vault_name)
    response = kv.make_rest_call(endpoint=endpoint, method='GET', manage_api_endpoint=True)
    return response


def delete_key_vault(config, params):
    kv = AzureKeyVault(config)
    subscription_id = kv.subscription_id
    resource_group = params.get('resource_group_name')
    vault_name = params.get('vault_name')
    endpoint = '/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults/{2}'
    endpoint = endpoint.format(subscription_id, resource_group, vault_name)
    response = kv.make_rest_call(endpoint=endpoint, method='DELETE', manage_api_endpoint=True)
    result = {
        "status": response.status_code,
        "result": "Successfully deleted the vault"
    }
    return result


def update_vault_access_policy(config, params):
    kv = AzureKeyVault(config)
    subscription_id = kv.subscription_id
    resource_group = params.get('resource_group_name')
    vault_name = params.get('vault_name')
    operationKind = params.get('operation_kind', '').lower()
    endpoint = '/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults/{2}/accessPolicies/{3}'
    endpoint = endpoint.format(subscription_id, resource_group, vault_name, operationKind)
    accessPolicies = params.get('accessPolicies', [])
    payload = {
        "properties": accessPolicies
    }
    response = kv.make_rest_call(endpoint=endpoint, method='PUT', data=payload, manage_api_endpoint=True)
    return response


def list_or_get_keys(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = params.get('vault_name', '')
    key_name = params.get('key_name', '')
    key_version = params.get('key-version', '') or ''
    endpoint = '{0}.vault.azure.net/keys'.format(vault_name)
    if key_name:
        endpoint += '/{0}/{1}'.format(key_name, key_version)
        response = kv.make_rest_call(endpoint=endpoint, method='GET')
        return response
    skip_token = params.get('skip_token')
    endpoint += '?$skiptoken={0}'.format(skip_token) if skip_token else ''
    payload = {}
    size = params.get('size')
    if size:
        payload["maxresults"] = size
    response = kv.make_rest_call(endpoint=endpoint, method='GET', params=payload)
    return response


def delete_key(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = params.get('vault_name')
    key_name = params.get('key_name', '')
    endpoint = '{0}.vault.azure.net/keys/{1}'.format(vault_name, key_name)
    response = kv.make_rest_call(endpoint=endpoint, method='DELETE')
    return response


def list_or_get_secret(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = params.get('vault_name')
    endpoint = '{0}.vault.azure.net/secrets'.format(vault_name)
    secret_name = params.get('secret_name', '')
    secret_version = params.get('secret_version', '') or ''
    if secret_name:
        endpoint += '/{0}/{1}'.format(secret_name, secret_version)
        response = kv.make_rest_call(endpoint=endpoint, method='GET')
        return response
    skip_token = params.get('skip_token')
    endpoint += '?$skiptoken={0}'.format(skip_token) if skip_token else ''
    payload = {}
    size = params.get('size')
    if size:
        payload["maxresults"] = size
    response = kv.make_rest_call(endpoint=endpoint, method='GET', params=payload)
    return response


def delete_secret(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = params.get('vault_name')
    secret_name = params.get('secret_name', '')
    endpoint = '{0}.vault.azure.net/secrets/{1}'.format(vault_name, secret_name)
    response = kv.make_rest_call(endpoint=endpoint, method='DELETE')
    return response


def list_or_get_certificate(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = params.get('vault_name')
    endpoint = '{0}.vault.azure.net/certificates'.format(vault_name)
    certificate_name = params.get('certificate_name', '')
    certificate_version = params.get('certificate-version', '') or ''
    if certificate_name:
        endpoint += '/{0}/{1}'.format(certificate_name, certificate_version)
        response = kv.make_rest_call(endpoint=endpoint, method='GET')
        return response
    skip_token = params.get('skip_token')
    endpoint += '?$skiptoken={0}'.format(skip_token) if skip_token else ''
    payload = {
        "includePending": params.get('includePending')
    }
    size = params.get('size')
    if size:
        payload["maxresults"] = size
    response = kv.make_rest_call(endpoint=endpoint, method='GET', params=payload)
    return response


def delete_certificate(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = params.get('vault_name')
    certificate_name = params.get('certificate_name', '')
    endpoint = '{0}.vault.azure.net/certificates/{1}'.format(vault_name, certificate_name)
    response = kv.make_rest_call(endpoint=endpoint, method='DELETE')
    return response


def get_certificate_policy(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = params.get('vault_name')
    certificate_name = params.get('certificate_name', '')
    endpoint = '{0}.vault.azure.net/certificates/{1}/policy'.format(vault_name, certificate_name)
    response = kv.make_rest_call(endpoint=endpoint, method='GET')
    return response


def get_versions(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = params.get('vault_name', '')
    name = params.get('name', '')
    obj = params.get('object', '').lower()
    endpoint = '{0}.vault.azure.net/{1}/{2}/versions'.format(vault_name, obj, name)
    skip_token = params.get('skip_token')
    endpoint += '?$skiptoken={0}'.format(skip_token) if skip_token else ''
    payload = {}
    size = params.get('size')
    if size:
        payload["maxresults"] = size
    response = kv.make_rest_call(endpoint=endpoint, method='GET', params=payload)
    return response


def check(config, connector_info):
    try:
        ms = MicrosoftAuth(config)
        config_id = config['config_id']
        if 'accessToken' in config and 'vaultAccessToken' in config:
            ms.validate_token(config, connector_info) and ms.validate_vault_token(config, connector_info)
        elif 'accessToken' not in config and 'vaultAccessToken' in config:
            token_resp = ms.generate_token()
            config['accessToken'] = token_resp.get('accessToken')
            config['expiresOn'] = token_resp.get('expiresOn')
            config['refresh_token'] = token_resp.get('refresh_token')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id']) and ms.validate_vault_token(config, connector_info)
        elif 'accessToken' in config and 'vaultAccessToken' not in config:
            token_resp = ms.generate_token(VAULT_SCOPE)
            config['vaultAccessToken'] = token_resp['accessToken']
            config['vaultExpiresOn'] = token_resp['expiresOn']
            config['vaultRefresh_token'] = token_resp.get('refresh_token')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id']) and ms.validate_vault_token(config, connector_info)
        else:
            token_resp = ms.generate_token()
            config['accessToken'] = token_resp.get('accessToken')
            config['expiresOn'] = token_resp.get('expiresOn')
            config['refresh_token'] = token_resp.get('refresh_token')
            token_resp = ms.generate_token(VAULT_SCOPE)
            config['vaultAccessToken'] = token_resp['accessToken']
            config['vaultExpiresOn'] = token_resp['expiresOn']
            config['vaultRefresh_token'] = token_resp.get('refresh_token')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id']) and ms.validate_vault_token(config, connector_info)
        config['config_id'] = config_id
        if config.get('use_vault'):
            get_credentials(config, {})
        return True
    except Exception as err:
        raise ConnectorError(str(err))


def get_credentials(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = config.get('vault_name')
    endpoint = '{0}.vault.azure.net/secrets/?'.format(vault_name)
    payload = {}
    size = params.get('size')
    if size:
        payload["maxresults"] = size
    response = kv.make_rest_call(endpoint=endpoint, method='GET', params=payload)
    formatted_response = []
    for secret in response.get('value', []):
        secret_name = secret.get('id').split('secrets/')[-1]
        formatted_response.append({"key": secret_name, "display_name": secret_name})
    return formatted_response


def get_credentials_details(config, params):
    formatted_response = [
        {
            "field_name": "Secret Value",
            "value": "*****"
        }
    ]
    return formatted_response


def get_credential(config, params):
    config['scope'] = VAULT_SCOPE
    kv = AzureKeyVault(config)
    vault_name = config.get('vault_name')
    secret_name = params.get('secret_id')
    endpoint = '{0}.vault.azure.net/secrets/{1}'.format(vault_name, secret_name)
    response = kv.make_rest_call(endpoint=endpoint, method='GET')
    return {"password": response.get('value')}


operations = {
    'list_key_vault': list_key_vault,
    'get_key_vault': get_key_vault,
    'delete_key_vault': delete_key_vault,
    'update_vault_access_policy': update_vault_access_policy,
    'list_keys': list_or_get_keys,
    'get_key': list_or_get_keys,
    'delete_key': delete_key,
    'list_secret': list_or_get_secret,
    'get_secret': list_or_get_secret,
    'delete_secret': delete_secret,
    'list_certificate': list_or_get_certificate,
    'get_certificate': list_or_get_certificate,
    'delete_certificate': delete_certificate,
    'get_certificate_policy': get_certificate_policy,
    'get_versions': get_versions,

    'get_credentials': get_credentials,
    'get_credentials_details': get_credentials_details,
    'get_credential': get_credential
}
