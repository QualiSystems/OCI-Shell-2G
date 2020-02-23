from cloudshell.cp.core.models import PrepareSubnetActionResult


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
        self.public = False
        request_cidr = None
        for attrs in self._subnet_service_attrs:
            if attrs.get("attributeName", "").lower() == "allocated cidr":
                self.cidr = attrs.get("attributeValue")
            elif attrs.get("attributeName", "").lower() == "public":
                self.public = attrs.get("attributeValue")
            elif attrs.get("attributeName", "").lower() == "requested cidr":
                request_cidr = attrs.get("attributeValue")
            elif attrs.get("attributeName", "").lower() == "allow all sandbox traffic":
                self.allow_sandbox_traffic = attrs.get("attributeValue")

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
    def __init__(self, json_request):
        self._json_request = json_request
        self._driver_request = json_request.get("driverRequest")
        self._actions = self._driver_request.get("actions")
        self._vcn_list = []
        self._keys_action_id = None
        self.is_default_flow = True

    @property
    def vcn_list(self):
        return self._vcn_list

    @property
    def key_action_id(self):
        return self._keys_action_id

    def parse_request(self):
        subnet_dict = {}
        main_vcn = None
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
            if "vcn" in subnet.alias.lower():
                vcn = VcnRequest()
                vcn.vcn_cidr = subnet.cidr
                vcn.vcn_action_id = subnet.subnet_action_id
                vcn.subnet_list.append(subnet)
                self._vcn_list.append(vcn)
            elif main_vcn:
                main_vcn.subnet_list.append(subnet)
