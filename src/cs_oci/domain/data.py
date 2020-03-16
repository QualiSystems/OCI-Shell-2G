import re

import ipaddress
from cloudshell.cp.core.models import PrepareSubnetActionResult

from cs_oci.helper.shell_helper import OciShellError


class VcnRequest(object):
    def __init__(self, action=None, is_main=False):
        self.vcn_cidr = None
        self.vcn_action_id = None
        self.is_main = is_main
        if action:
            self.vcn_cidr = action.get("actionParams", {}).get("cidr")
            self.vcn_action_id = action.get("actionId")
        self.subnet_list = []


class SubnetAttributes:
    def __init__(self, subnet_service_attrs=None):
        self._subnet_service_attrs = subnet_service_attrs or []
        self.allow_sandbox_traffic = None
        self.cidr = None
        self.is_vcn = False
        self.public = True
        request_cidr = None
        for attrs in self._subnet_service_attrs:
            if attrs.get("attributeName", "").lower() == "allocated cidr":
                self.cidr = attrs.get("attributeValue")
            elif attrs.get("attributeName", "").lower() == "public":
                self.public = attrs.get("attributeValue").lower() == "true"
            elif attrs.get("attributeName", "").lower() == "requested cidr":
                request_cidr = attrs.get("attributeValue")
            elif attrs.get("attributeName", "").lower() == "allow all sandbox traffic":
                self.allow_sandbox_traffic = attrs.get("attributeValue", "").lower() == "true"
            elif attrs.get("attributeName", "").lower() == "vcn id":
                self.is_vcn = True

        if request_cidr:
            self.cidr = request_cidr


class SubnetRequest(object):
    def __init__(self, action):
        self.subnet_action_id = action.get("actionId")
        subnet_services = action.get("actionParams", {}).get("subnetServiceAttributes", [])
        self.attributes = SubnetAttributes(subnet_services)
        self.cidr = self.attributes.cidr or action.get("actionParams", {}).get("cidr")
        default_alias = "Subnet {}".format(self.cidr)
        self.alias = action.get("actionParams", {}).get("alias", None)
        if not self.alias:
            self.alias = default_alias


class PrepareOCISubnetActionResult(PrepareSubnetActionResult):
    def __init__(self, virtual_network_id="", action_id='', success=True, info_message='', error_message='',
                 subnet_id=''):
        PrepareSubnetActionResult.__init__(self, action_id, success, info_message, error_message, subnet_id)
        self.virtual_network_id = virtual_network_id


class PrepareSandboxInfraRequest(object):
    def __init__(self, resource_config, json_request):
        self._json_request = json_request
        self._driver_request = json_request.get("driverRequest")
        self._actions = self._driver_request.get("actions")
        self._vcn_list = []
        self._keys_action_id = None
        self.is_default_flow = True
        self._resource_config = resource_config

    @property
    def vcn_list(self):
        return self._vcn_list

    @property
    def key_action_id(self):
        return self._keys_action_id

    def parse_request(self):
        subnet_dict = {}
        main_vcn = None
        does_vcn_act_as_subnet = False
        for action in self._actions:
            if action["type"] == "prepareCloudInfra":
                main_vcn = VcnRequest(action, True)
                self._vcn_list.append(main_vcn)
            elif action["type"] == "prepareSubnet":
                subnet = SubnetRequest(action)
                subnet_dict[subnet.subnet_action_id] = subnet
            elif action["type"] == "createKeys":
                self._keys_action_id = action.get("actionId")

        for subnet_id in subnet_dict:
            subnet = subnet_dict.get(subnet_id)
            if subnet.attributes.is_vcn:
                if not does_vcn_act_as_subnet:
                    does_vcn_act_as_subnet = True
                vcn = VcnRequest()
                vcn.vcn_cidr = subnet.cidr
                vcn.vcn_action_id = subnet.subnet_action_id
                vcn.subnet_list.append(subnet)
                self._vcn_list.append(vcn)
                cidr = subnet.cidr
                vcn_alias_match = re.search(r"(?P<name>^.*)\s+-\s+\d+\.", subnet.alias)
                if vcn_alias_match:
                    net = ipaddress.ip_network(cidr)
                    vcn_name = "{} - {}-{}".format(vcn_alias_match.groupdict().get("name", "VCN"),
                                                   net.network_address,
                                                   net.num_addresses)
                else:
                    vcn_name = "VCN-{}".format(cidr.replace("/", "-"))
                if subnet.alias != vcn_name:
                    self._resource_config.api.SetServiceName(self._resource_config.reservation_id,
                                                             subnet.alias,
                                                             vcn_name)
                    subnet.alias = vcn_name
            elif main_vcn:
                main_vcn.subnet_list.append(subnet)
        if does_vcn_act_as_subnet and any(x for x in subnet_dict.values() if not x.attributes.is_vcn):
            raise OciShellError("Mixed connectivity mode is unsupported: "
                                "please use only Subnet Services or only VCN Services")
