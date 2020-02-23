from copy import copy

import time
import json
import jsonpickle

from cloudshell.shell.core.driver_context import AutoLoadDetails, ResourceRemoteCommandContext

from cloudshell.cp.core import DriverRequestParser
from cloudshell.cp.core.models import DeployApp, DeployAppResult, DriverResponse, Attribute, ConnectSubnet, \
    PrepareSubnetActionResult, ConnectToSubnetActionResult
from cloudshell.cp.core.models import PrepareCloudInfraResult, CreateKeysActionResult, ActionResultBase

from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.session.logging_session import LoggingSessionContext

from cs_oci.domain.data import PrepareSandboxInfraRequest
from cs_oci.oci_flows.oci_networking_flow import OciNetworkInfraFlow
from data_model import OCIShellDriverResource
from cs_oci.domain.instance_details import InstanceDetails
from cs_oci.oci_clients.oci_ops import OciOps
from cs_oci.helper.shell_helper import set_command_result, create_vm_details, create_win_console_link, OciShellError


class OCIShellDriver(ResourceDriverInterface):
    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        self.request_parser = DriverRequestParser()
        self.deployments = dict()
        # Keys should be partial names of deployment paths
        self.deployments['OCI VM from Image'] = self.vm_from_image
        self.reservation_to_ssh_keys_map = {}

    def cleanup(self):
        pass

    def initialize(self, **kwargs):
        pass

    def Deploy(self, context, request=None, cancellation_context=None):
        """  """

        actions = self.request_parser.convert_driver_request_to_actions(request)
        resource_config = OCIShellDriverResource.create_from_context(context)
        resource_config.api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                                            'Request JSON: ' + request)
        with LoggingSessionContext(context) as logger:

            deploy_action = None
            subnet_actions = list()
            # subnet_actions = OrderedDict()
            for action in actions:
                if isinstance(action, DeployApp):
                    deploy_action = action
                if isinstance(action, ConnectSubnet):
                    subnet_actions.append(action)

            if deploy_action:

                deployment_name = deploy_action.actionParams.deployment.deploymentPath
                try:
                    deploy_method = next(self.deployments[deployment] for deployment in self.deployments.keys() if
                                         deployment_name.endswith(deployment))
                except StopIteration:
                    raise OciShellError('Could not find the deployment ' + deployment_name)
                results = deploy_method(resource_config, logger, deploy_action, subnet_actions, cancellation_context)
                return DriverResponse(results).to_driver_response_json()
            else:
                raise OciShellError('Failed to deploy VM')

    def vm_from_image(self, resource_config, logger, deploy_action, subnet_actions, cancellation_context):
        """
        :param logger:
        :param resource_config:
        :param deploy_action:
        :param cancellation_context:
        :return:
        :type subnet_actions: list<ConnectSubnet>
        """
        # Init CloudShell and OCI APIs
        logger.info("Starting Deployment from Image")
        oci_ops = OciOps(resource_config)
        secondary_subnet_actions = {}
        network_results = []

        # Read deployment attributes
        app_name = deploy_action.actionParams.appName
        vm_instance_details = InstanceDetails(deploy_action)

        primary_vnic_action = None
        if subnet_actions:
            subnet_actions.sort(key=lambda x: x.actionParams.vnicName)
            primary_vnic_action = subnet_actions[0]
            primary_vnic0_action = next((
                action for action in subnet_actions if action.actionParams.vnicName == "0"), None)
            if primary_vnic0_action:
                primary_vnic_action = primary_vnic0_action

            secondary_subnet_actions = copy(subnet_actions)
            secondary_subnet_actions.remove(primary_vnic_action)

            subnet_id = primary_vnic_action.actionParams.subnetId
            subnet = oci_ops.network_ops.get_subnet(subnet_id)
            if not subnet:
                raise OciShellError("Failed to retrieve subnet")
        else:
            vcn = oci_ops.network_ops.get_vcn(resource_config.reservation_id)
            subnets = oci_ops.network_ops.get_subnets(vcn.id)
            subnet = subnets[0]
            subnet_id = subnet.id

        availability_domain = subnet.availability_domain

        ssh_pub_key = oci_ops.get_public_key()

        instance = oci_ops.compute_ops.launch_instance(availability_domain=availability_domain,
                                                       app_name=app_name,
                                                       subnet_id=subnet_id,
                                                       ssh_pub_key=ssh_pub_key,
                                                       vm_details=vm_instance_details)
        instance_name = app_name + " " + instance.id.split(".")[-1][-10:]
        attributes = []

        try:
            user = vm_instance_details.user
            password = resource_config.api.DecryptPassword(vm_instance_details.password).Value
            credentials = oci_ops.compute_ops.get_windows_credentials(instance.id)
            if credentials:
                user, password = credentials

            attributes.append(Attribute("User", user))
            attributes.append(Attribute("Password", password))

            # set resource attributes (of the new resource) to use requested username and password

            vnic_attachments = oci_ops.compute_ops.get_vnic_attachments(instance.id)
            vnic_attachment = next((v for v in vnic_attachments if v), None)
            if not vnic_attachment:
                raise OciShellError("No vnic")
            vnic_details = oci_ops.network_ops.network_client.get_vnic(vnic_attachment.vnic_id)

            if primary_vnic_action:
                primary_interface_json = json.dumps({
                    'interface_id': vnic_details.data.id,
                    'IP': vnic_details.data.private_ip,
                    'Public IP': vnic_details.data.public_ip,
                    'MAC Address': vnic_details.data.mac_address
                })
                network_results.append(ConnectToSubnetActionResult(actionId=primary_vnic_action.actionId,
                                                                   interface=primary_interface_json))

            if vm_instance_details.inbound_ports:
                new_security_list_item = oci_ops.network_ops.add_security_list(
                    vcn_id=subnet.vcn_id,
                    security_list_name=instance_name,
                    inbound_ports=vm_instance_details.inbound_ports)

                if new_security_list_item:
                    oci_ops.network_ops.update_subnet_security_lists(subnet,
                                                                     security_list_id=new_security_list_item.data.id)

            oci_ops.compute_ops.update_instance_name(instance_name, instance.id)
            has_sec_public_ip = True
            for vnic_action in secondary_subnet_actions:
                vnic_public_ip = vnic_action.actionParams.isPublic
                if vnic_public_ip:
                    if has_sec_public_ip:
                        vnic_public_ip = vnic_action.actionParams.isPublic
                        has_sec_public_ip = False
                    else:
                        vnic_public_ip = False
                        message = "Unable to find secondary subnet"
                        secondary_subnet_name = oci_ops.network_ops.get_subnet(vnic_action.actionParams.subnetId).display_name
                        if secondary_subnet_name:
                            message = "Could not add public IP to VNIC in subnet {}, " \
                                      "to {}. Access possible" \
                                      " using private IP only.".format(secondary_subnet_name, instance_name)
                            resource_config.api.WriteMessageToReservationOutput(resource_config.reservation_id,
                                                                                "Warning, {}".format(message))
                        logger.warning(message)

                interface_json = oci_ops.attach_secondary_vnics(name=vnic_action.actionId,
                                                                subnet_id=vnic_action.actionParams.subnetId,
                                                                instance_id=instance.id,
                                                                src_dst_check=vm_instance_details.skip_src_dst_check,
                                                                is_public=vnic_public_ip)
                network_results.append(
                    ConnectToSubnetActionResult(actionId=vnic_action.actionId, interface=interface_json))
        except Exception as e:
            oci_ops.compute_ops.terminate_instance(instance.id)
            logger.exception("Failed to deploy {}:".format(app_name))
            raise OciShellError("Failed to deploy {} reason: {}".format(app_name, e.message))

        deploy_result = DeployAppResult(actionId=deploy_action.actionId,
                                        infoMessage="Deployment Completed Successfully",
                                        vmUuid=instance.id,
                                        vmName=instance_name,
                                        deployedAppAddress=vnic_details.data.private_ip,
                                        deployedAppAttributes=attributes,
                                        vmDetailsData=create_vm_details(
                                            resource_config,
                                            oci_ops,
                                            instance.display_name,
                                            deploy_action.actionParams.deployment.deploymentPath,
                                            instance))

        if cancellation_context.is_cancelled:
            oci_ops.compute_ops.terminate_instance(instance.id)
            return "deployment cancelled and deleted successfully"

        action_results = [deploy_result]
        action_results.extend(network_results)
        return action_results

    def DeleteInstance(self, context, ports):
        """ Delete a VM
        :param context: ResourceRemoteCommandContext
        :param ports: sub-resources to delete
        :return:
        """

        # Code to delete instance based on remote command context
        resource_config = OCIShellDriverResource.create_from_context(context)
        oci_ops = OciOps(resource_config)
        oci_ops.compute_ops.terminate_instance()
        name = context.remote_endpoints[0].fullname.split('/')[0]

        return "Successfully terminated instance " + name

    def remote_refresh_ip(self, context, cancellation_context, ports):
        """ Refresh the IP of the resource from the VM
        :type context ResourceRemoteCommandContext
        """

        resource_config = OCIShellDriverResource.create_from_context(context)

        oci_ops = OciOps(resource_config)
        instance_id = resource_config.remote_instance_id
        name = context.remote_endpoints[0].fullname.split('/')[0]
        vnic = oci_ops.get_primary_vnic(instance_id)
        resource_config.api.UpdateResourceAddress(name, vnic.private_ip)
        try:
            resource_config.api.SetAttributeValue(name, "Public IP",
                                                  vnic.public_ip)
        except:
            pass

    def PowerOff(self, context, ports):
        """ Power Off the VM represented by the resource
        :param context: ResourceRemoteCommandContext
        :param list[string] ports: the ports of the connection between the remote resource and the local resource, NOT IN USE!!!

        :type context ResourceRemoteCommandContext
        """

        resource_config = OCIShellDriverResource.create_from_context(context)

        oci_ops = OciOps(resource_config)
        instance_id = resource_config.remote_instance_id
        oci_ops.compute_ops.change_instance_state(instance_id, oci_ops.compute_ops.INSTANCE_STOP)
        name = context.remote_endpoints[0].fullname.split('/')[0]

        try:
            resource_config.api.SetResourceLiveStatus(name, 'OCOffline',
                                                      'Resource is powered off')
        except:  # if "OCOnline" live status is missing, revert to "Offline" live status
            resource_config.api.SetResourceLiveStatus(name, 'Offline',
                                                      'Resource is powered off')

        return "VM stopped successfully"

    # the name is by the Qualisystems conventions
    def PowerOn(self, context, ports):
        """ Powers on the remote vm
        :param ResourceRemoteCommandContext context: the context the command runs on
        :param list[string] ports: the ports of the connection between the remote resource and the local resource, NOT IN USE!!!

        :type context ResourceRemoteCommandContext
        """

        resource_config = OCIShellDriverResource.create_from_context(context)
        oci_ops = OciOps(resource_config)
        with resource_config.get_logger() as logger:
            instance_id = resource_config.remote_instance_id
            logger.info("Instance id: {}".format(instance_id))
            oci_ops.compute_ops.change_instance_state(instance_id, oci_ops.compute_ops.INSTANCE_START)
            name = context.remote_endpoints[0].fullname.split('/')[0]

            try:
                resource_config.api.SetResourceLiveStatus(name, 'OCOnline',
                                                          'Resource is powered off')
            except:  # if "OCOnline" live status is missing, revert to "Offline" live status
                resource_config.api.SetResourceLiveStatus(name, 'Online',
                                                          'Resource is powered off')

        return "VM started  successfully"

    # the name is by the Qualisystems conventions
    def PowerCycle(self, context, ports, delay):
        """ Perform PowerOff followed up by PowerOn after {delay} seconds - NOT IN USE
        :param context: ResourceRemoteCommandContext
        :param ports: list[string] ports: the ports of the connection between the remote resource and the local resource, NOT IN USE!!!
        :param delay: int : Seconds to delay between powering off and back on.
        :return:
        """

        resource_config = OCIShellDriverResource.create_from_context(context)
        output = self.PowerOff(context, ports)
        resource_config.api.WriteMessageToReservationOutput(resource_config.reservation_id, output)
        time.sleep(float(delay))
        output = self.PowerOn(context, ports)
        resource_config.api.WriteMessageToReservationOutput(resource_config.reservation_id, output)
        return

    def get_inventory(self, context):
        """
        :type context: models.QualiDriverModels.AutoLoadCommandContext
        """

        resource_config = OCIShellDriverResource.create_from_context(context)

        OciOps(resource_config)
        return AutoLoadDetails([], [])

    def get_vm_uuid(self, context, vm_name):
        """
        :param context: ResourceRemoteCommandContext
        :param vm_name: full resource name of the resource
        :return: UID of the VM in OCI
        """

        resource_config = OCIShellDriverResource.create_from_context(context)

        res_details = resource_config.api.GetResourceDetails(vm_name)
        return str(jsonpickle.encode(res_details.VmDetails.UID, unpicklable=False))

    def GetVmDetails(self, context, cancellation_context, requests):
        """
        Return VM Details JSON to the Quali Server for refreshing the VM Details pane
        :param context: ResourceRemoteCommandContext
        :param cancellation_context: bool - will become True if action is cancelled
        :param requests: str JSON - requests for VMs to refresh
        :return:
        """

        resource_config = OCIShellDriverResource.create_from_context(context)

        oci_ops = OciOps(resource_config)
        requests_json = json.loads(requests)
        vm_details_results = []
        for refresh_request in requests_json["items"]:
            vm_name = refresh_request["deployedAppJson"]["name"]
            deployment_service = refresh_request["appRequestJson"]["deploymentService"][
                "name"]
            instance_id = resource_config.api.GetResourceDetails(vm_name).VmDetails.UID
            instance = oci_ops.compute_ops.compute_client.get_instance(instance_id).data
            vm_details_results.append(
                create_vm_details(resource_config, oci_ops=oci_ops,
                                  vm_name=vm_name,
                                  deployment_service_name=deployment_service,
                                  instance=instance))
        return str(jsonpickle.encode(vm_details_results, unpicklable=False))

    def console(self, context, ports, connection_type, client_os):
        """Generates a command for a console access to an instance"""
        resource_config = OCIShellDriverResource.create_from_context(context)

        oci_ops = OciOps(resource_config)

        with LoggingSessionContext(context) as logger:
            instance_id = resource_config.remote_instance_id
            ssh_pub_key = oci_ops.get_public_key()

            result = oci_ops.compute_ops.create_instance_console(instance_id,
                                                                 compartment_ocid=resource_config.compartment_ocid,
                                                                 ssh_pub_key=ssh_pub_key,
                                                                 tags=resource_config.tags)
            if "win" in client_os.lower():
                if "vnc" in connection_type.lower():
                    response = create_win_console_link(console_id=result.data.id,
                                                       instance_id=instance_id,
                                                       region=resource_config.region,
                                                       linux_vnc_link=result.data.vnc_connection_string)
                else:
                    response = create_win_console_link(console_id=result.data.id,
                                                       instance_id=instance_id,
                                                       region=resource_config.region,
                                                       linux_ssh_link=result.data.connection_string)
            else:
                response = result.data.connection_string
                if "vnc" in connection_type.lower():
                    response = result.data.vnc_connection_string

            return "Console command is:\n{}\n".format(response)

    def set_as_routing_gateway(self, context, ports):
        """Generates a command for a console access to an instance"""
        resource_config = OCIShellDriverResource.create_from_context(context)

        oci_ops = OciOps(resource_config)

        with LoggingSessionContext(context) as logger:
            oci_ops.set_as_routing_gw()

    def _remote_save_snapshot(self, context, ports, snapshot_name):
        resource_config = OCIShellDriverResource.create_from_context(context)
        oci_ops = OciOps(resource_config)

        with LoggingSessionContext(context) as logger:
            instance_id = resource_config.remote_instance_id
            instance = oci_ops.compute_ops.compute_client.get_instance(instance_id)
            tags = resource_config.tags
            tags["InstanceId"] = instance_id

            oci_ops.create_volume_backup(instance, snapshot_name, tags)
            return "Backup {} created successfully".format(snapshot_name)

    def _remote_get_snapshots(self, context, ports):
        resource_config = OCIShellDriverResource.create_from_context(context)
        oci_ops = OciOps(resource_config)

        with LoggingSessionContext(context) as logger:
            instance_id = resource_config.remote_instance_id
            instance = oci_ops.compute_ops.compute_client.get_instance(instance_id)
            volume_backups = oci_ops.storage_client.list_boot_volume_backups(instance.data.compartment_id)
            return [backup.display_name for backup in volume_backups.data if
                    backup.freeform_tags["InstanceId"] == instance_id]

    def _remote_restore_snapshot(self, context, ports, snapshot_name):
        # ToDo for future implementation
        resource_config = OCIShellDriverResource.create_from_context(context)
        oci_ops = OciOps(resource_config)

        with LoggingSessionContext(context) as logger:
            self.PowerOff(context, ports)

    def PrepareSandboxInfra(self, context, request, cancellation_context):
        """
        Called by CloudShell Orchestration during the Setup process in order to populate information about the
        networking environment used by the sandbox
        :param context: ResourceCommandContext
        :param request: Actions to be performed to prepare the networking environment sent by CloudShell Server
        :param cancellation_context:
        :return:
        """

        resource_config = OCIShellDriverResource.create_from_context(context)
        with resource_config.get_logger() as logger:
            oci_ops = OciOps(resource_config)
            resource_config.api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                                                'Request JSON: ' + request)
            oci_networks = OciNetworkInfraFlow(oci_ops, logger, resource_config)
            json_request = json.loads(request)

            resource_config.api.WriteMessageToReservationOutput(resource_config.reservation_id,
                                                                'Preparing Sandbox Connectivity...')

        request_object = PrepareSandboxInfraRequest(json_request)
        request_object.parse_request()
        try:
            prepare_network_results = oci_networks.prepare_sandbox_infra(request_object)

            # if request_object.is_default_flow:
            #     prepare_network_results = oci_networks.prepare_default_sandbox_infra(request_object)
            # else:
            #     prepare_network_results = oci_networks.prepare_vcn_sandbox_infra(request_object)
        except Exception as e:
            oci_ops.network_ops.remove_vcn()
            raise

        # Set Keypair
        private_key, public_key = oci_ops.generate_rsa_key_pair()
        oci_ops.upload_keypairs(private_key=private_key,
                                public_key=public_key)

        prepare_network_results.append(CreateKeysActionResult(actionId=request_object.key_action_id,
                                                              infoMessage='',
                                                              accessKey=private_key))

        quali_api = resource_config.quali_api_helper
        quali_api.login()
        quali_api.attach_file_to_reservation(resource_config.reservation_id,
                                             private_key,
                                             "{}.pem".format(resource_config.reservation_id))

        return DriverResponse(prepare_network_results).to_driver_response_json()

    def CleanupSandboxInfra(self, context, request):
        """

        :param context:
        :param request:
        :return:
        """

        json_request = json.loads(request)
        resource_config = OCIShellDriverResource.create_from_context(context)
        oci_ops = OciOps(resource_config)
        cleanup_action_id = next(action["actionId"] for action in json_request["driverRequest"]["actions"] if
                                 action["type"] == "cleanupNetwork")

        oci_ops.network_ops.remove_vcn()
        oci_ops.remove_key_pairs()
        quali_api = resource_config.quali_api_helper
        quali_api.login()
        quali_api.remove_attached_files(resource_config.reservation_id)
        cleanup_result = ActionResultBase("cleanupNetwork", cleanup_action_id)

        return set_command_result({'driverResponse': {'actionResults': [cleanup_result]}})
