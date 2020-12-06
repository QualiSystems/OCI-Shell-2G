import json
import re
from copy import copy

import ipaddress

from cs_oci.helper.shell_helper import OciShellError


class InboundRule(object):
    def __init__(self, ports, cidr=None, protocol=None):
        self.ports = ports or "all"
        self.cidr = cidr or "0.0.0.0/0"
        if "/" not in self.cidr:
            self.cidr += "/32"
        self.protocol = protocol or "tcp"


class PrivateIP(object):
    def __init__(self, private_ip, name=""):
        self.name = name.strip()
        self.ip = private_ip.strip()


class DeploySubnet(object):
    def __init__(self, oci_ops, action_id, subnet_id, is_public_subnet=None, ip=None):
        self.action_id = action_id
        self.private_ip = ip
        self.subnet_id = subnet_id
        self._oci_ops = oci_ops
        self.is_public_subnet = is_public_subnet
        self._oci_subnet = None

    @property
    def oci_subnet(self):
        if not self._oci_subnet:
            self._oci_subnet = self._oci_ops.network_ops.get_subnet(self.subnet_id)
        return self._oci_subnet


class InstanceDetails(object):
    def __init__(self, deploy_action, subnet_actions, oci_ops):
        self._oci_ops = oci_ops
        self._deployment_path = deploy_action.actionParams.deployment.deploymentPath
        self._deploy_attribs = deploy_action.actionParams.deployment.attributes
        self._app_resource = deploy_action.actionParams.appResource.attributes
        self._inbound_ports = None
        self._subnet_actions = subnet_actions
        self._primary_subnet_action = None
        self._secondary_subnet_actions = []
        self._vcn_id = None
        self._user = None
        self._public_ip_attr = None
        self._password = None

    @property
    def vcn_id(self):
        if not self._vcn_id:
            self._vcn_id = self.primary_subnet.oci_subnet.freeform_tags.get("VCN_ID")
        return self._vcn_id

    @property
    def availability_domain(self):
        return self.primary_subnet.oci_subnet.availability_domain

    @property
    def image_id(self):
        return self._deploy_attribs.get("{}.Image ID".format(self._deployment_path), "")

    @property
    def public_ip(self):
        public_ip_str = self._deploy_attribs.get("{}.Add Public IP".format(self._deployment_path), "")

        return public_ip_str.lower() == "true"

    @property
    def cloud_init_params(self):
        return self._deploy_attribs.get("{}.Cloud Init Script Data".format(self._deployment_path), "")

    @property
    def requested_private_ips(self):
        result = []
        private_ips_str = self._deploy_attribs.get("{}.Requested Private IP".format(self._deployment_path), "")
        if private_ips_str:
            for private_ip in map(unicode.strip, private_ips_str.strip(";").split(";")):
                result.append(PrivateIP(*private_ip.split(":")[::-1]))
        return result

    @property
    def primary_subnet(self):
        if not self._primary_subnet_action:
            self._parse_subnet_actions()
        return self._primary_subnet_action

    @property
    def secondary_subnets(self):
        if not self._secondary_subnet_actions:
            self._parse_subnet_actions()
        return self._secondary_subnet_actions

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
        return self._app_resource.get(self.user_attr_name)

    @property
    def user_attr_name(self):
        if not self._user:
            self._user = next((x for x in self._app_resource
                               if x.lower().endswith(".user") or x.lower() == "user"),
                              "User")
        return self._user

    @property
    def public_ip_attr_name(self):
        if not self._public_ip_attr:
            self._public_ip_attr = next((x for x in self._app_resource if x.lower().endswith(".public ip")),
                                        "Public IP")
        return self._public_ip_attr

    @property
    def password(self):
        return self._app_resource.get(self.password_attr_name)

    @property
    def password_attr_name(self):
        return next((x for x in self._app_resource
                     if x.lower().endswith(".password") or x.lower() == "password"),
                    "Password")

    def _parse_inbound_ports(self):
        raw_data = self._deploy_attribs.get("{}.Inbound Ports".format(self._deployment_path), "")
        self._inbound_ports = []
        for item in raw_data.split(";"):
            rule_match = re.search(r"^(((?P<cidr>\d+.\d+.\d+.\d+(/\d+)*):)?"
                                   r"(?P<protocol>\w+):)?(?P<ports>(all|\d+([-,]\d+)*))$",
                                   item, re.IGNORECASE)
            if rule_match:
                self._inbound_ports.append(InboundRule(**rule_match.groupdict()))

    def _parse_subnet_actions(self):
        if len(self._subnet_actions) < 2 or not self._subnet_actions:
            if not self._subnet_actions:
                vcn = self._oci_ops.network_ops.get_vcn()
                self._vcn_id = vcn.id
                default_subnet = self._oci_ops.network_ops.get_subnets(vcn.id)[0]

                subnet_id = default_subnet.id
                cidr = default_subnet.cidr_block
                action_id = None
            else:
                subnet_id = self._subnet_actions[0].actionParams.subnetId
                cidr = self._subnet_actions[0].actionParams.cidr
                # cidr = self._subnet_actions[0].actionParams.subnetServiceAttributes.get("Allocated CIDR")
                action_id = self._subnet_actions[0].actionId

            self._primary_subnet_action = DeploySubnet(oci_ops=self._oci_ops,
                                                       subnet_id=subnet_id,
                                                       action_id=action_id)
            if self.requested_private_ips:
                if len(self.requested_private_ips) < 2:
                    self._primary_subnet_action.private_ip = self.requested_private_ips[0]
                else:
                    self._primary_subnet_action.private_ip = self.identify_ip(self.requested_private_ips, cidr)

            return

        subnet_actions = copy(self._subnet_actions)
        ip_address_list = copy(self.requested_private_ips)
        primary_subnet_action = None
        primary_ip = None
        if ip_address_list:
            subnet_actions.sort(key=lambda x: x.actionParams.vnicName)
            primary_ip = ip_address_list[0]
            primary_subnet_action = next((s for s in subnet_actions
                                          if s.actionParams.vnicName == primary_ip.name),
                                         None)
            if not primary_subnet_action:
                primary_subnet_action = next(
                    (s for s in subnet_actions
                     if self.check_ip_in_subnet((
                            s.actionParams.cidr),
                        primary_ip.ip)),
                    None)

        if not primary_subnet_action:
            primary_subnet_action = subnet_actions[0]

        self._primary_subnet_action = DeploySubnet(oci_ops=self._oci_ops,
                                                   action_id=primary_subnet_action.actionId,
                                                   subnet_id=primary_subnet_action.actionParams.subnetId,
                                                   ip=primary_ip)

        subnet_actions.remove(primary_subnet_action)
        if primary_ip:
            ip_address_list.remove(primary_ip)
        if ip_address_list:
            for ip in ip_address_list:
                for subnet in subnet_actions:
                    cidr = self._get_cidr(subnet)
                    if self.identify_ip([ip], cidr):
                        ip_address = ip
                        if subnet:
                            self._secondary_subnet_actions.append(
                                DeploySubnet(oci_ops=self._oci_ops,
                                             action_id=subnet.actionId,
                                             subnet_id=subnet.actionParams.subnetId,
                                             is_public_subnet=subnet.actionParams.isPublic,
                                             ip=ip_address))
                        break
        else:
            subnet_actions.sort(key=lambda x: x.actionParams.vnicName)
            for subnet in subnet_actions:
                ip_address = None
                if ip_address_list:
                    ip_address = next((ip for ip in ip_address_list if ip.name == subnet.actionParams.vnicName), "")
                    if not ip_address:
                        cidr = self._get_cidr(subnet)
                        ip_address = self.identify_ip(ip_address_list, cidr)
                    if ip_address:
                        ip_address_list.remove(ip_address)
                if subnet:
                    self._secondary_subnet_actions.append(DeploySubnet(oci_ops=self._oci_ops,
                                                                       action_id=subnet.actionId,
                                                                       subnet_id=subnet.actionParams.subnetId,
                                                                       is_public_subnet=subnet.actionParams.isPublic,
                                                                       ip=ip_address))

    def _get_cidr(self, subnet):
        return subnet.actionParams.subnetServiceAttributes.get("Requested CIDR") or \
               subnet.actionParams.subnetServiceAttributes.get("Allocated CIDR")

    def identify_ip(self, ip_list, network):
        for ip in ip_list:
            if self.check_ip_in_subnet(cidr=network, ip=ip.ip):
                return ip

    def check_ip_in_subnet(self, cidr, ip):
        ip_addr = ipaddress.ip_address(unicode(ip))
        if ip_addr in ipaddress.ip_network(unicode(cidr)):
            return True
