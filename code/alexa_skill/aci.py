import logging
import requests
import os
import json
from sys import exit
from multiprocessing.dummy import Pool
import re

import utils
from lab_env import *

# disable warnings from SSL/TLS certificates
requests.packages.urllib3.disable_warnings()


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


class Aci:
    """
    Handles requests to ACI APIs
    """
    def __init__(self, host, port, user, password):
        self.logger = setup_logging(self.__class__.__name__)
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.base_url = self.create_base_url()
        self.auth_url = self.create_auth_url()
        self.cookie = self.get_auth_cookie()

    def create_base_url(self):
        """
        Helper function to create a ACI API endpoint URL
        """
        return 'https://{}:{}'.format(self.host, self.port)

    def create_auth_url(self):
        """
        Helper function to create a ACI API authentication URL
        """
        return '{}/api/aaaLogin.json'.format(self.base_url)

    def get_auth_cookie(self):
        """
        Authenticates with controller and returns a cookie to be used in subsequent API invocations
        """
        self.logger.info('Getting cookie from {}'.format(self.auth_url))
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": self.user,
                    "pwd": self.password
                }
            }
        }

        try:
            session = requests.Session()
            session.verify = False
            response = session.post(self.auth_url, data=json.dumps(payload), timeout=5)
            response.raise_for_status()
            return response.cookies
        except requests.exceptions.RequestException as err:
            self.logger.error('Request to API has failed. {}'.format(err))
            self.logger.debug('Error details:', exc_info=True)

    def renew_auth_cookie(self):
        """
        Renews API authentication cookie.
        """
        self.cookie = self.get_auth_cookie()

    def rest_request(self, method, resource, params=None, data=None, headers={}):
        """
        Sends requests to REST API.
        """
        url = self.base_url + resource

        retries = 0
        while retries < 2:
            retries += 1
            content_type = {'Content-Type': 'application/json'}
            headers.update(content_type)
            try:
                self.logger.info('Sending API request to {}'.format(url))
                response = requests.request(
                    method=method,
                    url=url,
                    cookies=self.cookie,
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
                if response.status_code == 403 and 'Token timeout' in response.text:
                    self.logger.info('Authentication token has expired. Will renew it. Retry #{}'.format(retries))
                    self.renew_auth_cookie()
                    continue
                else:
                    self.logger.error('Received an HTTP error. {}'.format(err))
                    return response
            except requests.exceptions.RequestException as err:
                self.logger.error('Request to API has failed. {}'.format(err))
                self.logger.debug('Error details:', exc_info=True)

    def create_tenant(self, tenant_name, vrf_name=None):
        """
        Creates a Tenant
        """
        self.logger.info('Running function using parameters: %s, %s', tenant_name, vrf_name)
        resource = '/api/node/mo/uni/tn-{}.json'.format(tenant_name)
        payload = {
            "fvTenant": {
                "attributes": {
                    "descr": "",
                    "dn": "uni/tn-{}".format(tenant_name),
                    "name": tenant_name,
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": "",
                    "status": "created"
                },
                "children": []
            }
        }

        if vrf_name:
            # Update payload with VRF information.
            vrf = [
                {
                    "fvCtx": {
                        "attributes": {
                            "bdEnforcedEnable": "no",
                            "descr": "",
                            "knwMcastAct": "permit",
                            "name": vrf_name,
                            "nameAlias": "",
                            "ownerKey": "",
                            "ownerTag": "",
                            "pcEnfDir": "ingress",
                            "pcEnfPref": "enforced"
                        },
                        "children": []
                    }
                }
            ]
            payload['fvTenant']['children'] = vrf

        return self.rest_request('POST', resource, data=json.dumps(payload))

    def delete_tenant(self, tenant_name):
        """
        Deletes a Tenant
        """
        self.logger.info('Running function using parameters: %s', tenant_name)
        resource = '/api/node/mo/uni/tn-{}.json'.format(tenant_name)
        return self.rest_request('DELETE', resource)

    def exists_tenant(self, tenant_name):
        """
        Checks if a Tenant exists
        """
        self.logger.info('Running function using parameters: %s', tenant_name)
        resource = '/api/node/mo/uni/tn-{}.json'.format(tenant_name)
        response = self.rest_request('GET', resource)
        exits = response.json().get('totalCount') != "0"
        return exits

    def get_fabric_health(self):
        """
        Get the fabric overall health (las 5min)
        """
        self.logger.info('Running function.')
        resource = '/api/node/mo/topology/HDfabricOverallHealth5min-0.json'
        return self.rest_request('GET', resource)

    # The following methods are specifically for the CL demo.
    def toggle_provide_contract(self, provide=False):
        """
        This method is specific for the CL demo. It configures APIC to Provide Contract
        "SmartCtrl_Portal_Web_Contract" in Internal EPG "SmartCtrlPortal". It assumes that specific AP and EPG are
        already created.
        """
        self.logger.info('Running function using parameters: %s', provide)
        resource = '/api/node/mo/uni/tn-iot/ap-SmartCtrl-AP/epg-SmartCtrlPortal.json'
        status = 'created' if provide else 'deleted'
        payload = {
            "fvRsProv": {
                "attributes": {
                    "tnVzBrCPName": "SmartCtrl_Portal_Web_Contract",
                    "status": status
                },
                "children": []
            }
        }
        return self.rest_request('POST', resource, data=json.dumps(payload))

    def toggle_consume_contract(self, consume=False):
        """
        This method is specific for the CL demo. It configures APIC to Consume Contract
        "SmartCtrl_Portal_Web_Contract" from the External EPG "iot-L3out". It assumes that specific AP and EPG are
        already created.
        """
        self.logger.info('Running function using parameters: %s', consume)
        resource = '/api/node/mo/uni/tn-iot/out-iot-L3out/instP-Bulbs_SGT.json'
        status = 'created' if consume else 'deleted'
        payload = {
            "fvRsCons": {
                "attributes": {
                    "tnVzBrCPName": "SmartCtrl_Portal_Web_Contract",
                    "status": status
                },
                "children": []
            }
        }
        return self.rest_request('POST', resource, data=json.dumps(payload))

    def get_ep_details(self, name):
        """
        This method is specific for the CL demo.
        Given an EP name, it returns the following information about it:
        IP, VLAN, Leaf nodes and ports.
        """
        pass
        vm_dn_list = self._get_vm_by_name(name)

        if not vm_dn_list:
            return None

        # Use only the first VM found
        vm_dn = vm_dn_list[0]
        ep_details = self._get_ep_by_vm(vm_dn)
        return ep_details

    def _get_vm_by_name(self, name):
        """
        This method is specific for the CL demo.
        Gets a list of distinguished names (DNs) for VMs that contain the given string in its name.
        """
        self.logger.info('Running function using parameters: %s', name)
        resource = ('/api/node/mo/comp/prov-VMware/ctrlr-[candid_vcenter]-candid_vcenter.json'
                    '?query-target=children&target-subtree-class=compVm'
                    '&query-target-filter=wcard(compVm.name,"{}")'.format(name))
        response = self.rest_request('GET', resource)
        if response.status_code != 200:
            return None
        if response.json()['totalCount'] == "0":
            return []
        virtual_machines = response.json()['imdata']
        dn_list = []
        for vm in virtual_machines:
            dn = vm['compVm']['attributes']['dn']
            dn_list.append(dn)

        return dn_list

    def _get_ep_by_vm(self, vm_dn):
        """
        Gets a VMM End Point given the VM distinguished name (DN)
        """
        self.logger.info('Running function using parameters: {}'.format(vm_dn))
        resource = ('/api/node/mo/uni/tn-iot/ap-SmartCtrl-AP/epg-SmartCtrlPortal.json?query-target=children'
                    '&target-subtree-class=fvCEp&rsp-subtree=children&rsp-subtree-class=fvRsCEpToPathEp,fvRsToVm')
        response = self.rest_request('GET', resource)
        if response.status_code != 200 or response.json()['totalCount'] == "0":
            return None
        all_vmm_endpoints = response.json()['imdata']
        endpoint = search_vm(all_vmm_endpoints, vm_dn)
        if not endpoint:
            ep = None
        else:
            ip = endpoint['fvCEp']['attributes'].get('ip')
            vlan = endpoint['fvCEp']['attributes']['encap'].split('-')[1]
            locations = self._get_ep_locations(endpoint)
            ep = {'ip': ip, 'vlan': vlan, 'locations': locations}

        return ep

    def _get_ep_locations(self, endpoint):
        locations = []
        for child in endpoint['fvCEp']['children']:
            path = child.get('fvRsCEpToPathEp')
            if not path:
                continue
            tgn = path['attributes']['tDn']
            node = re.search(r'/paths-(\d+)/', tgn)
            intf_pg = re.search(r'\[(.*)\]', tgn)
            if node and intf_pg:
                node = node.group(1)
                intf_pg = intf_pg.group(1)
                ports = self._get_ports_in_intfpg(node, intf_pg)
                locations.append({'node': node, 'ports': ports})
        return locations

    def _get_ports_in_intfpg(self, node, intf_pg):
        """
        Gets a list of ports that belong to a Interface Profile Group in a specific Leaf.
        """
        self.logger.info('Running function using parameters: {}, {}'.format(node, intf_pg))
        resource = ('/api/node/mo/uni/infra/funcprof/accbundle-{}.json?rsp-subtree-include=full-deployment'
                    '&target-node={}'
                    '&target-path=AccBaseGrpToEthIf'.format(intf_pg, node))
        response = self.rest_request('GET', resource)
        if response.status_code != 200:
            return None
        if response.json()['totalCount'] == "0":
            self.logger.info('Empty list of records returned.')
            return []
        bndlgrp_children = response.json()['imdata'][0]['infraAccBndlGrp']['children']
        ports = []
        for bndlgrp_child in bndlgrp_children:
            node = bndlgrp_child.get('pconsNodeDeployCtx')
            if not node:
                continue
            node_children = node['children']
            for node_child in node_children:
                ctx = node_child.get('pconsResourceCtx')
                if not ctx:
                    continue
                ctx_dn = re.search(r'/phys-\[eth(\d+)/(\d+)\]', ctx['attributes']['ctxDn'])
                if ctx_dn:
                    ports.append({'card': ctx_dn.group(1), 'port': ctx_dn.group(2)})
        return ports


def search_vm(endpoints, target_vm):
    for endpoint in endpoints:
        children = endpoint['fvCEp']['children']
        for child in children:
            vm = child.get('fvRsToVm')
            if not vm:
                continue
            if vm['attributes']['tDn'] == target_vm:
                return endpoint


if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)
    module_logger = setup_logging()

    module_logger.info('Testing module locally...')
    # Uncomment the following lines to test the module locally

    aci = Aci(APIC_HOST, APIC_PORT, APIC_USER, APIC_PASSWORD)
    if not aci.cookie:
        print('Unable to obtain an authentication cookie.')
        exit(1)

    print('\n====> Cookie')
    print(aci.cookie)

    # Find VMs
    print(aci.get_ep_details('SmartCtrl_Server2'))
    exit(0)

    # Create a Tenant and a VRF
    tenant = 'Student1'
    vrf = 'Student1-VRF'
    print('\n====> Creating tenant: {}, with VRF: {}'.format(tenant, vrf))
    response = aci.create_tenant(tenant, vrf)
    print('Response:', response.status_code)
    if response.status_code == 200:
        print('Tenant successfully created!')
    elif response.status_code == 400 and 'already exists' in response.text:
        print('Tenant {} already exists'.format(tenant))
    else:
        print('Error creating tenant.')

    # Check if a Tenant exists
    tenant = 'Student1'
    print('\n====> Checking if tenant {} exists'.format(tenant))
    print(aci.exists_tenant(tenant))

    # Delete a Tenant
    tenant = 'Student1'
    print('\n====> Deleting tenant: {}'.format(tenant))
    response = aci.delete_tenant(tenant)
    if response.status_code == 200:
        print('Tenant successfully deleted!')
    else:
        print('Error deleting tenant.')

    # Fabric Health
    health = aci.get_fabric_health().json()['imdata'][0]['fabricOverallHealthHist5min']['attributes'].get('healthAvg')
    print('\n====> Overall Fabric Health (5min): {}'.format(health))

    # Allow SmartCtrl_talk to Light Bulbs.
    pool = Pool(2)
    thread_timeout = 8640
    operations = []
    operations.append((aci.toggle_provide_contract, {'provide': True}))
    operations.append((aci.toggle_consume_contract, {'consume': True}))
    data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
    pool.close()
    pool.join()
    print(data[0].text, data[1].text)
