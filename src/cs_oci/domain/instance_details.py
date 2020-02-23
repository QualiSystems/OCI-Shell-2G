import re


class InboundRule(object):
    def __init__(self, ports, cidr=None, protocol=None):
        self.ports = ports or "all"
        self.cidr = cidr or "0.0.0.0/0"
        if "/" not in self.cidr:
            self.cidr += "/32"
        self.protocol = protocol or "tcp"


class InstanceDetails(object):
    def __init__(self, deploy_action):
        self._deployment_path = deploy_action.actionParams.deployment.deploymentPath
        self._deploy_attribs = deploy_action.actionParams.deployment.attributes
        self._app_resource = deploy_action.actionParams.appResource.attributes
        self._inbound_ports = None

    @property
    def image_id(self):
        return self._deploy_attribs.get("{}.Image ID".format(self._deployment_path), "")

    @property
    def public_ip(self):
        public_ip_str = self._deploy_attribs.get("{}.Add Public IP".format(self._deployment_path), "")

        return public_ip_str.lower() == "true"

    @property
    def skip_src_dst_check(self):
        public_ip_str = self._deploy_attribs.get("{}.Skip VNIC src or dst check".format(self._deployment_path), "")

        return public_ip_str.lower() == "true"

    @property
    def vm_shape(self):
        return self._deploy_attribs.get("{}.VM Shape".format(self._deployment_path), "")

    @property
    def inbound_ports(self):
        if not self._inbound_ports:
            self._parse_inbound_ports()
        return self._inbound_ports

    @property
    def user(self):
        return self._app_resource.get("User")

    @property
    def password(self):
        return self._app_resource.get("Password")

    def _parse_inbound_ports(self):
        raw_data = self._deploy_attribs.get("{}.Inbound Ports".format(self._deployment_path), "")
        self._inbound_ports = []
        for item in raw_data.split(";"):
            rule_match = re.search(r"^(((?P<cidr>\d+.\d+.\d+.\d+(/\d+)*):)?"
                                   r"(?P<protocol>\w+):)?(?P<ports>(all|\d+([-,]\d+)*))$",
                                   item, re.IGNORECASE)
            if rule_match:
                self._inbound_ports.append(InboundRule(**rule_match.groupdict()))
