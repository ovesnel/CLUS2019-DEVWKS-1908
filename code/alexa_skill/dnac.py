import logging
import requests
from time import time, sleep
import os
from multiprocessing.dummy import Pool
import json
from sys import exit

import utils
from lab_env import *

# disable warnings from SSL/TLS certificates
requests.packages.urllib3.disable_warnings()

RETRY_INTERVAL = 1
DNAC_API_INTENT_URL = '/dna/intent/api/v1'
DNAC_API_CFS_URL = '/api/v2/data/customer-facing-service'
DNAC_API_AUTH_URL = '/api/system/v1/auth/token'
DNAC_API_TASK_URL = '/api/v1/task'


def setup_logging(class_name=None):
    """
    Rewrite the default AWS Lambda logging handler format
    """
    class_name = '.' + class_name if class_name else ''
    logger = logging.getLogger()
    if IN_AWS:
        formatter = logging.Formatter(
            (
                '[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(aws_request_id)s\t'
                '%(threadName)s\t%(name)s.%(module)s{}.%(funcName)s\t'
                '%(message)s'
            ).format(class_name)
        )
    else:
        formatter = logging.Formatter(
            (
                '[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t'
                '%(threadName)s\t%(name)s.%(module)s{}.%(funcName)s\t'
                '%(message)s'
            ).format(class_name)
        )

    if logger.handlers:
        handler = logger.handlers[0]
        handler.setFormatter(formatter)

    return logger


# Custom exception definitions
class TaskTimeoutError(Exception):
    pass


class TaskError(Exception):
    pass


class InvalidVnName(Exception):
    pass


class InvalidResponseReceived(Exception):
    """
    Received response does not contains 'response' keyword.
    """
    pass


class Dnac:
    """
    Handles requests to DNAC APIs
    """
    def __init__(self, host, port, user, password):
        self.logger = setup_logging(self.__class__.__name__)
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.base_url = self.create_base_url()
        self.auth_url = self.create_auth_url()
        self.session = None
        self.token = self.get_auth_token()

    def create_base_url(self):
        """
        Helper function to create a DNAC API endpoint URL
        """
        return 'https://{}:{}'.format(self.host, self.port)

    def create_auth_url(self):
        """
        Helper function to create a DNAC API authentication URL
        """
        return 'https://{}:{}{}'.format(self.host, self.port, DNAC_API_AUTH_URL)

    def get_auth_token(self):
        """
        Authenticates with controller and returns a token to be used in subsequent API invocations
        """
        self.logger.info('Requesting token from {}'.format(self.auth_url))
        try:
            session = requests.Session()
            session.auth = (self.user, self.password)
            session.verify = False

            response = session.post(self.auth_url, timeout=5)
            response.raise_for_status()

            self.session = session
            token = response.json().get('Token')
            return token
        except requests.exceptions.RequestException as err:
            self.logger.error('Request to API has failed. {}'.format(err))
            self.logger.debug('Error details:', exc_info=True)

    def renew_auth_token(self):
        """
        Renews API authentication token.
        """
        self.token = self.get_auth_token()

    def rest_request(self, method, resource, params=None, data=None, headers={}):
        """
        Sends requests to REST API.
        """
        url = self.base_url + resource

        retries = 0
        while retries < 2:
            retries += 1
            auth_header = {'x-auth-token': self.token}
            content_type = {'Content-Type': 'application/json'}
            headers.update(auth_header)
            headers.update(content_type)
            try:
                self.logger.info('Sending API request to {}'.format(url))
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params or {},
                    data=data or {},
                    verify=False
                )
                self.logger.info('HTTP Response: {} {}'.format(response.status_code, response.reason))
                response.raise_for_status()
                self.logger.debug('HTTP Response: {}. Received data: {}'.format(response.status_code, response.text))
                return response
            except requests.exceptions.HTTPError as err:
                error_details = response.json().get('exp')
                if response.status_code == 401 and error_details == 'token expired':
                    self.logger.info('Authentication token has expired. Will renew it. Retry #{}'.format(retries))
                    self.renew_auth_token()
                    continue
                else:
                    self.logger.error('Request to API has failed. {}'.format(err))
                    raise
            except requests.exceptions.RequestException as err:
                self.logger.error('Request to API has failed. {}'.format(err))
                self.logger.debug('Error details:', exc_info=True)

    def wait_on_task(self, task_id, timeout=(5 * RETRY_INTERVAL), retry_interval=RETRY_INTERVAL):
        """
        Waits for the specified task to complete
        """
        resource = '{}/{}'.format(DNAC_API_TASK_URL, task_id)
        start_time = time()

        self.logger.info('Waiting for task={} to complete. Using retry_interval={}s and timeout={}s'
                         .format(task_id, timeout, retry_interval))

        while True:
            result = self.rest_request('GET', resource)
            response = result.json().get('response')

            if 'endTime' in response:
                return response
            else:
                if timeout and (start_time + timeout < time()):
                    raise TaskTimeoutError('Task {} did not complete within the specified timeout ({} seconds)'
                                           .format(task_id, timeout))

                self.logger.info('Task={} has not completed yet. Sleeping {} seconds...'
                                 .format(task_id, retry_interval))
                sleep(retry_interval)

            # if response.get('isError'):
            #     raise TaskError('Task {} had error {}'.format(task_id, response.get('progress')))

    def list_network_device(self, **kwargs):
        """
        Lists network devices
        """
        self.logger.info('Running function using parameters: %s', kwargs)
        resource = '{}/network-device'.format(DNAC_API_INTENT_URL)
        response = self.rest_request('GET', resource, params=kwargs)
        return response.json().get('response')

    def get_current_network_health(self):
        """
        Returns Current Overall Network Health information by Device category.
        """
        current_time = int(time() * 1000)
        self.logger.info('Running function using parameters: %s', current_time)
        resource = '{}/network-health'.format(DNAC_API_INTENT_URL)
        response = self.rest_request('GET', resource, params={'timestamp': current_time})
        return response.json().get('response')

    def list_virtual_network(self, **kwargs):
        """
        Lists Virtual Network Contexts
        """
        self.logger.info('Running function using parameters: %s', kwargs)
        resource = '{}/virtualnetworkcontext'.format(DNAC_API_CFS_URL)
        response = self.rest_request('GET', resource, params=kwargs)
        return response.json().get('response')

    def create_virtual_network(self, payload, asynch=True):
        """
        Creates a Virtual Network Context
        """
        self.logger.info('Running function using parameters: %s', payload)
        resource = '{}/virtualnetworkcontext'.format(DNAC_API_CFS_URL)
        payload = json.dumps(payload)
        response = self.rest_request('POST', resource, data=payload).json().get('response')
        if asynch:
            return response
        else:
            return self.wait_on_task(response.get('taskId'))

    def delete_virtual_network_by_id(self, vn_id, asynch=True):
        """
        Deletes a Virtual Network Context
        """
        self.logger.info('Running function using parameters: %s', vn_id)
        resource = '{}/virtualnetworkcontext/{}'.format(DNAC_API_CFS_URL, vn_id)
        response = self.rest_request('DELETE', resource).json().get('response')
        if asynch:
            return response
        else:
            return self.wait_on_task(response.get('taskId'))

    def delete_virtual_network_by_name(self, vn_name, asynch=True):
        """
        Deletes a Virtual Network Context
        """
        self.logger.info('Running function using parameters: %s', vn_name)
        vn_id = self.get_virtual_network_id(vn_name)
        return self.delete_virtual_network_by_id(vn_id, asynch)

    def get_virtual_network_by_id(self, vn_id):
        """
        Retrieves a Virtual Network Context
        """
        self.logger.info('Running function using parameters: %s', vn_id)
        resource = '{}/virtualnetworkcontext/{}'.format(DNAC_API_CFS_URL, vn_id)
        response = self.rest_request('GET', resource)
        return response.json().get('response')

    def get_virtual_network_by_name(self, vn_name):
        """
        Retrieves a Virtual Network Context
        """
        self.logger.info('Running function using parameters: %s', vn_name)
        resource = '{}/virtualnetworkcontext'.format(DNAC_API_CFS_URL)
        params = {'name': vn_name}
        response = self.rest_request('GET', resource, params=params)
        return response.json().get('response')

    def get_virtual_network_id(self, vn_name):
        """
        Get a Virtual Network Context ID given its name.
        """
        virtual_network = self.get_virtual_network_by_name(vn_name)
        if len(virtual_network):
            return virtual_network[0].get('id')
        else:
            raise InvalidVnName('There is not VN named: {}'.format(vn_name))

    def exists_virtual_network(self, vn_name):
        """
        Checks if a Virtual Network Context exists
        """
        self.logger.info('Running function using parameters: %s', vn_name)
        resource = '{}/virtualnetworkcontext'.format(DNAC_API_CFS_URL)
        params = {'name': vn_name}
        response = self.rest_request('GET', resource, params=params).json().get('response')
        return bool(response)


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    module_logger = setup_logging()

    module_logger.info('Testing module locally...')
    # Uncomment the following lines to test the module locally

    dnac = Dnac(DNAC_HOST, DNAC_PORT, DNAC_USER, DNAC_PASSWORD)
    if not dnac.token:
        print('Unable to obtain an authentication token.')
        exit(1)

    print('\n====> Token')
    print(dnac.token)

    # Current Network Health
    health = dnac.get_current_network_health()[0].get('healthScore')
    print('\n====> Overall Network health: {}'.format(health))

    # List of network devices
    print('\n====> List of Network Devices:')
    # print(json.dumps(dnac.list_network_device(), indent=2))

    # List of Virtual Networks
    print('\n====> List of Virtual Networks:')
    # vns = dnac.list_virtual_network()
    # print('Number of Virtual Networks:', len(vns))
    # print(json.dumps(vns, indent=2))

    vnname = 'TEST_VN'

    # Create a Virtual Network
    data = [
        {
            "name": vnname,
            "virtualNetworkContextType": "ISOLATED"
        }
    ]
    print('\n====> Creating a Virtual Network: {}'.format(vnname))
    response = dnac.create_virtual_network(data, asynch=False)
    print(json.dumps(response, indent=2))

    # Get a Virtual Network context by Name
    print('\n====> Get a Virtual Network Context by Name: {}'.format(vnname))
    print(json.dumps(dnac.get_virtual_network_by_name(vnname), indent=2))

    # Get a Virtual Network context by Id
    vnid = dnac.get_virtual_network_id(vnname)
    print('\n====> Get a Virtual Network Context by Id: {}'.format(vnid, vnname))
    print(json.dumps(dnac.get_virtual_network_by_id(vnid), indent=2))

    # Delete a Virtual Network context
    print('\n==== Deleting Virtual Network: {} ===='.format(vnname))
    response = dnac.delete_virtual_network_by_name(vnname, asynch=False)
    print(json.dumps(response, indent=2))

    # Get a Virtual Network context ID given its name
    vnname = 'INFRA_VN'
    print('\n====> Get a Virtual Network Context ID given its name:')
    print('Virtual Network context Name: {}'.format(vnname))
    print('Virtual Network context ID: {}'.format(dnac.get_virtual_network_id(vnname)))

    # Multi-threading
    pool = Pool(4)
    thread_timeout = 8640
    operations = []
    operations.append((dnac.exists_virtual_network, {'vn_name': vnname}))
    data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
    pool.close()
    pool.join()
    print(data)
