import re
from copy import copy
import ipaddress

from cloudshell.api.cloudshell_api import AttributeNameValue
from cloudshell.cp.core.models import PrepareCloudInfraResult

from cs_oci.domain.data import PrepareOCISubnetActionResult


class OciNetworkInfraFlow(object):
    def __init__(self, oci_ops, logger, resource_config):
        """

        :type resource_config: data_model.OCIShellDriverResource
        :type oci_ops: cs_oci.oci_clients.oci_ops.OciOps
        """

        self._oci_ops = oci_ops
        self._logger = logger
        self._resource_config = resource_config

    def get_answer(self, vcn_action_id):
        prepare_network_result = PrepareCloudInfraResult(vcn_action_id)

        return prepare_network_result

    def prepare_sandbox_infra(self, request_object):
        result_list = []
        traffic_vcn_list = []
        availability_domain = self._oci_ops.get_availability_domain_name()
        for vcn_request in request_object.vcn_list:
            if vcn_request.is_main:
                prepare_network_result = self.get_answer(vcn_request.vcn_action_id)
                prepare_network_result.securityGroupId = self._resource_config.reservation_id
                prepare_network_result.networkId = self._resource_config.reservation_id
                result_list.append(prepare_network_result)

                if vcn_request.subnet_list:
                    add_inet_gw = False
                    if any(x for x in vcn_request.subnet_list if x.attributes.public):
                        add_inet_gw = True
                    vcn = self._oci_ops.network_ops.create_vcn(vcn_request.vcn_cidr,
                                                               add_inet_gw=add_inet_gw)
                    prepare_network_result.securityGroupId = vcn.default_security_list_id
                    prepare_network_result.networkId = vcn.id
                else:
                    continue
            else:
                vcn_subnet = vcn_request.subnet_list[0]

                is_public = vcn_subnet.attributes.public

                oci_vcn_name = "{}-{}".format(self._resource_config.reservation_id, vcn_subnet.alias)
                vcn = self._oci_ops.network_ops.create_vcn(vcn_subnet.cidr, oci_vcn_name, is_public)
                self._resource_config.api.SetServiceAttributesValues(self._resource_config.reservation_id,
                                                                     vcn_subnet.alias,
                                                                     [AttributeNameValue("VCN Id", vcn.id)])

                if vcn_subnet.attributes.allow_sandbox_traffic:
                    traffic_vcn_list.append(vcn)

            result_list.extend(self.create_subnets(vcn_request.subnet_list, vcn.id, availability_domain))
        vcn_dict = self._convert_list(traffic_vcn_list)
        for vcn in vcn_dict:
            # vcn_id = vcn_id.id
            # src_vcn_name = "To-{}".format(vcn_id.display_name)

            for dst_vcn in vcn_dict.get(vcn):
                # dst_vcn_id = dst_vcn.id

                # dst_vcn_name = "To-{}".format(dst_vcn.display_name)

                # src_lpg = self._oci_ops.network_ops.create_lpg(vcn_id, dst_vcn_name, dst_vcn_id)
                # dst_lpg = self._oci_ops.network_ops.create_lpg(dst_vcn_id, src_vcn_name, vcn_id)
                # self._oci_ops.network_ops.connect_lpgs(src_lpg.id, dst_lpg.id)
                # self._oci_ops.network_ops.add_lpg_route(vcn_id.default_route_table_id, dst_vcn.cidr_block, src_lpg.id)
                # self._oci_ops.network_ops.add_lpg_route(dst_vcn.default_route_table_id, vcn_id.cidr_block, dst_lpg.id)
                self._oci_ops.network_ops.allow_local_traffic(vcn.default_security_list_id, dst_vcn.cidr_block)
                self._oci_ops.network_ops.allow_local_traffic(dst_vcn.default_security_list_id, vcn.cidr_block)
                vcn_dict.get(dst_vcn).remove(vcn)

        return result_list

    def _convert_list(self, traffic_vcn_list):
        result = dict()
        for vcn in traffic_vcn_list:
            dst_vcn_list = copy(traffic_vcn_list)
            dst_vcn_list.remove(vcn)
            result[vcn] = dst_vcn_list
        return result

    def create_subnets(self, subnet_list, vcn_id, availability_domain):
        """

        :param availability_domain:
        :param List<cs_oci.domain.data.SubnetRequest> subnet_list:
        :param vcn_id:
        :return:
        """
        subnet_results = []

        for subnet_request in subnet_list:
            route_table = self._oci_ops.network_ops.create_route_table(vcn_id, subnet_request.alias)
            subnet = self._oci_ops.network_ops.create_subnet(subnet_request.cidr,
                                                             subnet_request.alias,
                                                             vcn_id,
                                                             route_table.id,
                                                             availability_domain)
            subnet_result = PrepareOCISubnetActionResult()
            subnet_result.actionId = subnet_request.subnet_action_id
            subnet_result.subnetId = subnet.id
            subnet_result.virtual_network_id = vcn_id
            subnet_result.infoMessage = "Success"
            subnet_results.append(subnet_result)
            if subnet_request.attributes.public:
                self._oci_ops.network_ops.add_inet_gw_route(route_table.id, vcn_id=vcn_id)
        return subnet_results
