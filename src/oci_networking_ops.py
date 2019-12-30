import oci
from oci import pagination


class OciNetworkOps(object):
    DEFAULT_STATIC_CIDR = "0.0.0.0/0"

    def __init__(self, resource_config):
        """

        :type resource_config: src.data_model.OCIShellDriverResource
        """
        config = resource_config.oci_config
        self._resource_config = resource_config
        self.network_client = oci.core.VirtualNetworkClient(config)
        self.network_client_ops = oci.core.VirtualNetworkClientCompositeOperations(self.network_client)

    def get_vcn(self):
        """
        Find a Vcn by reservation_id.
        :return: The Vcn
        :rtype: core_models.Vcn
        """

        result = pagination.list_call_get_all_results(
            self.network_client.list_vcns,
            self._resource_config.compartment_ocid,
            display_name=self._resource_config.reservation_id
        )
        for vcn in result.data:
            if self._resource_config.reservation_id == vcn.display_name:
                return vcn

    def get_subnet(self, vcn_id, subnet_cidr=None):
        """
        Find a unique Subnet by name.
        :param vcn_id: The OCID of the VCN which will own the subnet.
        :type vcn_id: str
        :param subnet_cidr: Subnet CIDR.
        :type subnet_cidr: str
        :return: The Subnet
        :rtype: core_models.Subnet
        """
        result = pagination.list_call_get_all_results(
            self.network_client.list_subnets,
            self._resource_config.compartment_ocid,
            vcn_id
        )

        print result
        if not subnet_cidr and result.data:
            return result.data
        for item in result.data:
            if subnet_cidr == item.cidr_block:
                return item

    def get_service_gateways(self, vcn_id):
        """
        Find a unique Subnet by name.
        :param vcn_id: The OCID of the VCN which will own the subnet.
        :type vcn_id: str
        :return: The Subnet
        :rtype: core_models.Subnet
        """
        result = pagination.list_call_get_all_results(
            self.network_client.list_service_gateways,
            self._resource_config.compartment_ocid,
            vcn_id=vcn_id
        )

        return result.data

    def get_inet_gateways(self, vcn_id):
        """
        Find a unique Subnet by name.
        :param vcn_id: The OCID of the VCN which will own the subnet.
        :type vcn_id: str
        :return: The Subnet
        :rtype: core_models.Subnet
        """
        result = pagination.list_call_get_all_results(
            self.network_client.list_internet_gateways,
            self._resource_config.compartment_ocid,
            vcn_id=vcn_id
        )

        return result.data

    def add_security_list(self, vcn_id, security_list_name, inbound_ports):
        # 31.154.25.138
        # 130.61.210.23
        inbound_ports_map = {
            "tcp": oci.core.models.TcpOptions,
            "icmp": oci.core.models.IcmpOptions,
            "udp": oci.core.models.UdpOptions,
            "all": ""
        }
        inbound_ports_protocol_map = {"icmp": "1", "tcp": "6", "udp": "17", "icmpv6": "58"}
        security_list_ingress_rules = []
        # inbound_ports_list = inbound_ports.split(";")
        for port in inbound_ports:
            rule_type = inbound_ports_map.get(port.protocol)
            if not rule_type:
                continue

            rule_parameters = {
                        "protocol": inbound_ports_protocol_map.get(port.protocol),
                        "source": port.cidr
                    }
            if "all" not in port.protocol:
                rules_to_add_list = port.ports.split(",")
                for rule_ports in rules_to_add_list:
                    try:
                        if "-" in rule_ports:
                            rule_ports_list = map(int, rule_ports.split("-"))
                            min_port = min(rule_ports_list)
                            max_port = max(rules_to_add_list)
                            port_range = oci.core.models.PortRange(min=min_port, max_port=max_port)
                        else:
                            port_range = oci.core.models.PortRange(min=int(rule_ports), max=int(rule_ports))
                    except ValueError:
                        continue
                    rule_parameters["{}_options".format(port.protocol)] = rule_type(destination_port_range=port_range)
                    security_list_ingress_rules.append(oci.core.models.IngressSecurityRule(**rule_parameters))

        if security_list_ingress_rules:
            return self.network_client_ops.create_security_list_and_wait_for_state(
                oci.core.models.CreateSecurityListDetails(
                    vcn_id=vcn_id,
                    display_name=security_list_name,
                    freeform_tags=self._resource_config.tags,
                    compartment_id=self._resource_config.compartment_ocid,
                    ingress_security_rules=security_list_ingress_rules,
                    egress_security_rules=[oci.core.models.EgressSecurityRule(destination=self.DEFAULT_STATIC_CIDR,
                                                                              protocol="all")]
                ),
                [oci.core.models.SecurityList.LIFECYCLE_STATE_AVAILABLE]
            )

    def configure_default_security_rule(self):
        vcn = self.get_vcn()
        security_list = self.network_client.get_security_list(vcn.default_security_list_id)
        security_list_update_details = oci.core.models.UpdateSecurityListDetails()
        security_list_update_details.egress_security_rules = security_list.data.egress_security_rules
        new_ingress_list = []
        for rule in security_list.data.ingress_security_rules:
            if rule.tcp_options and (rule.tcp_options.destination_port_range.max == 22 or
                                     rule.tcp_options.destination_port_range == 22):
                continue
            new_ingress_list.append(rule)
        # adding rule to allow internal subnet communication
        new_ingress_list.append(oci.core.models.IngressSecurityRule(source=vcn.cidr_block, protocol="all"))
        security_list_update_details.ingress_security_rules = new_ingress_list
        self.update_security_list(security_list.data.id, security_list_update_details)

    def update_security_list(self, security_list_id, update_security_list_details):
        self.network_client_ops.update_security_list_and_wait_for_state(
            security_list_id,
            update_security_list_details,
            [oci.core.models.SecurityList.LIFECYCLE_STATE_AVAILABLE]
        )

    def update_subnet_security_lists(self, subnet, security_list_id):
        new_security_list = subnet.security_list_ids
        new_security_list.append(security_list_id)
        self.network_client_ops.update_subnet_and_wait_for_state(
            subnet.id,
            oci.core.models.UpdateSubnetDetails(security_list_ids=new_security_list),
            [oci.core.models.Subnet.LIFECYCLE_STATE_AVAILABLE])

    def create_vcn(self, vcn_cidr):
        if vcn_cidr:
            vcn = self.get_vcn()

            if not vcn:
                new_vcn = self.network_client_ops.create_vcn_and_wait_for_state(
                    oci.core.models.CreateVcnDetails(
                        cidr_block=vcn_cidr,
                        display_name=self._resource_config.reservation_id,
                        freeform_tags=self._resource_config.tags,
                        compartment_id=self._resource_config.compartment_ocid
                    ),
                    [oci.core.models.Vcn.LIFECYCLE_STATE_AVAILABLE]
                )
                vcn = new_vcn.data
                default_route_table = self.network_client.get_route_table(vcn.default_route_table_id)
                route_rules = default_route_table.data.route_rules
                inet_gw = self.network_client_ops.create_internet_gateway_and_wait_for_state(
                    oci.core.models.CreateInternetGatewayDetails(
                        vcn_id=vcn.id,
                        display_name=self._resource_config.reservation_id,
                        freeform_tags=self._resource_config.tags,
                        is_enabled=True,
                        compartment_id=self._resource_config.compartment_ocid),
                    [oci.core.models.InternetGateway.LIFECYCLE_STATE_AVAILABLE]
                )
                default_static_rule = oci.core.models.RouteRule(
                    cidr_block=None,
                    destination=self.DEFAULT_STATIC_CIDR,
                    destination_type='CIDR_BLOCK',
                    network_entity_id=inet_gw.data.id
                )
                route_rules.append(default_static_rule)
                update_route_table_details = oci.core.models.UpdateRouteTableDetails(
                    route_rules=route_rules,
                    freeform_tags=self._resource_config.tags)
                self.network_client_ops.update_route_table_and_wait_for_state(
                    vcn.default_route_table_id,
                    update_route_table_details,
                    wait_for_states=[oci.core.models.RouteTable.LIFECYCLE_STATE_AVAILABLE]
                )
            return vcn

    def create_subnet(self, subnet_cidr, name, vcn_ocid, availability_domain):
        subnet = self.get_subnet(vcn_id=vcn_ocid,
                                 subnet_cidr=subnet_cidr)
        if not subnet:
            new_subnet = self.network_client_ops.create_subnet_and_wait_for_state(
                oci.core.models.CreateSubnetDetails(
                    compartment_id=self._resource_config.compartment_ocid,
                    availability_domain=availability_domain,
                    freeform_tags=self._resource_config.tags,
                    display_name=name,
                    vcn_id=vcn_ocid,
                    cidr_block=subnet_cidr
                ),
                [oci.core.models.Subnet.LIFECYCLE_STATE_AVAILABLE]
            )
            subnet = new_subnet.data
        return subnet

    def remove_vcn(self):
        vcn = self.get_vcn()
        if vcn:
            subnets = self.get_subnet(vcn_id=vcn.id) or []
            service_gateways = self.get_service_gateways(vcn_id=vcn.id) or []
            internet_gateways = self.get_inet_gateways(vcn_id=vcn.id) or []
            for subnet in subnets:
                self.network_client_ops.delete_subnet_and_wait_for_state(
                    subnet.id,
                    [oci.core.models.Subnet.LIFECYCLE_STATE_TERMINATED])
            update_route_table_details = oci.core.models.UpdateRouteTableDetails(route_rules=[])
            self.network_client_ops.update_route_table_and_wait_for_state(
                vcn.default_route_table_id,
                update_route_table_details,
                wait_for_states=[oci.core.models.RouteTable.LIFECYCLE_STATE_AVAILABLE]
            )
            for service_gw in service_gateways:
                self.network_client_ops.delete_service_gateway_and_wait_for_state(
                    service_gw.id,
                    [oci.core.models.ServiceGateway.LIFECYCLE_STATE_TERMINATED]
                )
            security_lists = self.network_client.list_security_lists(self._resource_config.compartment_ocid, vcn.id)
            for security_list in security_lists.data:
                if vcn.default_security_list_id == security_list.id:
                    continue
                self.network_client_ops.delete_security_list_and_wait_for_state(
                    security_list.id,
                    [oci.core.models.SecurityList.LIFECYCLE_STATE_TERMINATED])
            for internet_gw in internet_gateways:
                self.network_client_ops.delete_internet_gateway_and_wait_for_state(
                    internet_gw.id,
                    wait_for_states=[oci.core.models.InternetGateway.LIFECYCLE_STATE_TERMINATED]
                )

            self.network_client_ops.delete_vcn_and_wait_for_state(
                vcn.id,
                [oci.core.models.Vcn.LIFECYCLE_STATE_TERMINATED])
