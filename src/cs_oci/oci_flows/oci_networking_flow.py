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
                    vcn = self._oci_ops.network_ops.create_vcn(vcn_request.vcn_cidr)
                    prepare_network_result.securityGroupId = vcn.default_security_list_id
                    prepare_network_result.networkId = vcn.id
                else:
                    continue
            else:
                vcn_subnet = vcn_request.subnet_list[0]
                # cidr = vcn_subnet.cidr
                # vcn_alias_match = re.search(r"(?P<name>^.*)\s+-\s+\d+\.", vcn_subnet.alias)
                # if vcn_alias_match:
                #     net = ipaddress.ip_network(cidr)
                #     vcn_name = "{} - {}-{}".format(vcn_alias_match.groupdict().get("name", "VCN"),
                #                                    net.network_address,
                #                                    net.num_addresses)
                # else:
                #     vcn_name = "VCN-{}".format(cidr.replace("/", "-"))

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
            # vcn_id = vcn.id
            # src_vcn_name = "To-{}".format(vcn.display_name)

            for dst_vcn in vcn_dict.get(vcn):
                # dst_vcn_id = dst_vcn.id

                # dst_vcn_name = "To-{}".format(dst_vcn.display_name)

                # src_lpg = self._oci_ops.network_ops.create_lpg(vcn_id, dst_vcn_name, dst_vcn_id)
                # dst_lpg = self._oci_ops.network_ops.create_lpg(dst_vcn_id, src_vcn_name, vcn_id)
                # self._oci_ops.network_ops.connect_lpgs(src_lpg.id, dst_lpg.id)
                # self._oci_ops.network_ops.add_lpg_route(vcn.default_route_table_id, dst_vcn.cidr_block, src_lpg.id)
                # self._oci_ops.network_ops.add_lpg_route(dst_vcn.default_route_table_id, vcn.cidr_block, dst_lpg.id)
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
            subnet = self._oci_ops.network_ops.create_subnet(subnet_request.cidr,
                                                             subnet_request.alias,
                                                             vcn_id,
                                                             availability_domain)
            subnet_result = PrepareOCISubnetActionResult()
            subnet_result.actionId = subnet_request.subnet_action_id
            subnet_result.subnetId = subnet.id
            subnet_result.virtual_network_id = vcn_id
            subnet_result.infoMessage = "Success"
            subnet_results.append(subnet_result)
        return subnet_results

    # def prepare_default_sandbox_infra(self, request_object):
    #     subnet_results = []
    #
    #     availability_domain = self._oci_ops.get_availability_domain_name()
    #
    #     vcn = self._oci_ops.network_ops.create_vcn(request_object.vcn.vcn_cidr)
    #     prepare_network_result = self.get_answer(request_object.vcn.vcn_action_id)
    #     prepare_network_result.securityGroupId = vcn.default_security_list_id
    #     prepare_network_result.networkId = vcn.id
    #
    #     for action_id in request_object.subnets_dict:
    #         subnet_cidr, subnet_alias = request_object.subnet_dict.get(action_id)
    #         subnet = self._oci_ops.network_ops.create_subnet(subnet_cidr,
    #                                                          subnet_alias,
    #                                                          vcn.id,
    #                                                          availability_domain)
    #         subnet_result = PrepareOCISubnetActionResult()
    #         subnet_result.actionId = action_id
    #         subnet_result.subnetId = subnet.id
    #         subnet_result.virtual_network_id = vcn.id
    #         subnet_result.infoMessage = "Success"
    #         subnet_results.append(subnet_result)
    #
    #     prepare_network_result.infoMessage = 'PrepareConnectivity finished successfully'
    #
    #     response = [prepare_network_result]
    #     response.extend(subnet_results)
    #     return response
    #
    # def prepare_vcn_sandbox_infra(self, request_object):
    #     subnet_results = []
    #     reservation_id = self._resource_config.reservation_id
    #
    #     availability_domain = self._oci_ops.get_availability_domain_name()
    #
    #     prepare_network_result = self.get_answer(request_object.vcn.vcn_action_id)
    #     prepare_network_result.securityGroupId = reservation_id
    #     prepare_network_result.networkId = reservation_id
    #     # self._oci_ops.network_ops.configure_default_security_rule()
    #
    #     for action_id in request_object.subnets_dict:
    #         vcn_subnet_details = request_object.subnets_dict.get(action_id)
    #         vcn_name = "{}-VCN-{}".format(reservation_id, vcn_subnet_details.cidr)
    #         vcn = self._oci_ops.network_ops.create_vcn(vcn_subnet_details.cidr,
    #                                                    vcn_name)
    #         subnet = self._oci_ops.network_ops.create_subnet(vcn_subnet_details.cidr,
    #                                                          vcn_subnet_details.alias,
    #                                                          vcn.id,
    #                                                          availability_domain)
    #         subnet_result = PrepareOCISubnetActionResult()
    #         subnet_result.actionId = action_id
    #         subnet_result.subnetId = subnet.id
    #         subnet_result.virtual_network_id = vcn.id
    #         subnet_result.infoMessage = "Success"
    #         subnet_results.append(subnet_result)
    #         self._resource_config.api.SetServiceAttributesValues(reservation_id,
    #                                                              vcn_subnet_details.alias,
    #                                                              [AttributeNameValue("VCN Id", vcn.id)])
    #         self._resource_config.api.SetServiceName(reservation_id,
    #                                                  vcn_subnet_details.alias,
    #                                                  vcn_name)
    #
    #     prepare_network_result.infoMessage = 'PrepareConnectivity finished successfully'
    #
    #     response = [prepare_network_result]
    #     response.extend(subnet_results)
    #     return response
