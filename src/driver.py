import re
from copy import copy

import time
import json
import jsonpickle
import oci

from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.driver_context import AutoLoadDetails, ResourceRemoteCommandContext

from cloudshell.cp.core import DriverRequestParser
from cloudshell.cp.core.models import DeployApp, DeployAppResult, DriverResponse, VmDetailsData, VmDetailsProperty, \
    VmDetailsNetworkInterface, Attribute, ConnectSubnet, PrepareSubnetActionResult, ConnectToSubnetActionResult
from cloudshell.cp.core.models import PrepareCloudInfraResult, CreateKeysActionResult, ActionResultBase

from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.session.logging_session import LoggingSessionContext
from oci import pagination
from oci.core import VirtualNetworkClientCompositeOperations
from oci.core.models import AttachVnicDetails, CreateVnicDetails

from data_model import OCIShellDriverResource


class OCIShellDriver(ResourceDriverInterface):
    STATIC_CIDR = "0.0.0.0/0"

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

    def _set_command_result(self, result, unpicklable=False):
        """
        Serializes output as JSON and writes it to console output wrapped with special prefix and suffix
        :param result: Result to return
        :param unpicklable: If True adds JSON can be deserialized as real object.
                            When False will be deserialized as dictionary
        """
        # we do not need to serialize an empty response from the vCenter
        if result is None:
            return

        json_result = jsonpickle.encode(result, unpicklable=unpicklable)
        result_for_output = str(json_result)
        return result_for_output

    def _connect_oracle_session(self, resource_config):
        """
        Connects API sessions for OCI ComputeClient, VirtualNetworkClient and BlockStorageClient
        :param OCIShellDriverResource resource_config:
        :return: 
        """

        self.config = {
            "user": resource_config.api_user_id,
            "key_file": resource_config.api_key_file_path,
            "pass_phrase": resource_config.api_key_passphrase,
            "fingerprint": resource_config.api_key_file_fingerprint,
            "tenancy": resource_config.tenant_id,
            "region": resource_config.region
        }
        self.compute_client = oci.core.ComputeClient(self.config)
        self.network_client = oci.core.VirtualNetworkClient(self.config)
        self.storage_client = oci.core.BlockstorageClient(self.config)
        self.identity_client = oci.identity.IdentityClient(self.config)
        self.network_client_ops = VirtualNetworkClientCompositeOperations(self.network_client)
        self.compute_client_ops = oci.core.ComputeClientCompositeOperations(self.compute_client)
        self.storage_client_ops = oci.core.BlockstorageClientCompositeOperations(self.storage_client)

    def _get_connected_instance_id(self, context, api=None):
        """ Retrieve UID of the VM the resource represents
        :param context: 
        :return: 
        """

        if not api:
            api = CloudShellSessionContext(context).get_api()
        parent_connected_resource = api.GetResourceDetails(context.remote_endpoints[0].fullname.split('/')[0])
        try:
            instance_id = [attribute.Value for attribute in parent_connected_resource.ResourceAttributes if
                           attribute.Name == 'VM_UUID'][0]
        except:
            instance_id = parent_connected_resource.VmDetails.UID
        return instance_id

    def _get_val_by_key_suffix(self, dict_instance, suffix):
        """ Helper function - get the attribute value for an attribute in a dictionary by its Suffix
        :param dict_instance: Dictionary to search on
        :param suffix: the suffix to look for
        :return: 
        """
        try:
            return next(val for att, val in dict_instance.items() if att.endswith(suffix))
        except:
            raise KeyError("Given key is not in dictionary")

    def initialize(self, **kwargs):
        pass

    def Deploy(self, context, request=None, cancellation_context=None):
        """  """

        actions = self.request_parser.convert_driver_request_to_actions(request)
        api = CloudShellSessionContext(context).get_api()
        # api.WriteMessageToReservationOutput(context.reservation.reservation_id, 'Request JSON: ' + request)

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
                raise Exception('Could not find the deployment ' + deployment_name)
            results = deploy_method(context, api, deploy_action, subnet_actions, cancellation_context)
            return DriverResponse(results).to_driver_response_json()
        else:
            raise Exception('Failed to deploy VM')

    def vm_from_image(self, context, api, deploy_action, subnet_actions, cancellation_context):
        """
        :type subnet_actions: list<ConnectSubnet>
        :type context: ResourceCommandContext
        """
        # Init CloudShell and OCI APIs
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Deployment from Image")
            resource_config = OCIShellDriverResource.create_from_context(context)
            self._connect_oracle_session(resource_config)
            compute_client_composite_operations = oci.core.ComputeClientCompositeOperations(self.compute_client)
            secondary_subnet_actions = {}
            network_results = []

            # Read deployment attributes
            app_name = deploy_action.actionParams.appName
            deploy_attribs = deploy_action.actionParams.deployment.attributes
            vcn = self._get_unique_vcn_by_name(resource_config.compartment_ocid, context.reservation.reservation_id)
            if not vcn:
                raise Exception("Failed to locate appropriate VCN.")
            subnets = self._get_unique_subnet_by_cidr(resource_config.compartment_ocid, vcn_id=vcn.id)
            subnet = subnets[0]
            subnet_id = subnet.id
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
                subnet = next((s for s in subnets if s.id == subnet_id), None)
                if not subnet:
                    raise Exception("Failed to retrieve subnet")

            availability_domain = subnet.availability_domain

            image_id = self._get_val_by_key_suffix(deploy_attribs, "Image ID")
            public_ip_str = self._get_val_by_key_suffix(deploy_attribs, "Public IP")
            public_ip = public_ip_str.lower() == "true"
            vm_shape = self._get_val_by_key_suffix(deploy_attribs, "VM Shape")
            inbound_ports = self._get_val_by_key_suffix(deploy_attribs, "Inbound Ports")

            try:
                user = self._get_val_by_key_suffix(deploy_attribs, "User")
                password = self._get_val_by_key_suffix(deploy_attribs, "Password")
            except:
                user = ""
                password = ""

            # ToDo replace this part with ssh keys retrieving from oci bucket
            keys_path = resource_config.keypairs_path
            if not keys_path.endswith("\\"):
                keys_path += "\\"
            ssh_pub_key_path = "{}{}.pub".format(keys_path, resource_config.default_keypair)
            default_ssh_pub_key = str(open(ssh_pub_key_path).read())
            ssh_pub_key = default_ssh_pub_key

            new_inst_details = oci.core.models.LaunchInstanceDetails()
            # CreateVnicDetails
            new_inst_details.availability_domain = availability_domain
            new_inst_details.compartment_id = resource_config.compartment_ocid
            new_inst_details.subnet_id = subnet_id
            new_inst_details.display_name = app_name
            new_inst_details.freeform_tags = self._get_tags(context)
            new_inst_details.create_vnic_details = CreateVnicDetails(assign_public_ip=public_ip,
                                                                     display_name=context.reservation.reservation_id,
                                                                     subnet_id=subnet_id)
            new_inst_details.shape = vm_shape
            new_inst_details.image_id = image_id
            new_inst_details.metadata = {'ssh_authorized_keys': ssh_pub_key}

            # Create the VM
            launch_instance_response = compute_client_composite_operations.launch_instance_and_wait_for_state(
                new_inst_details,
                wait_for_states=[oci.core.models.Instance.LIFECYCLE_STATE_RUNNING],
                operation_kwargs={"retry_strategy": oci.retry.DEFAULT_RETRY_STRATEGY})
            instance = launch_instance_response.data

            if not instance:
                raise RuntimeError("Timeout when waiting for VM to Power on")

            instance_name = app_name + " " + instance.id.split(".")[-1][-10:]
            attributes = []

            try:
                instance_credentials = self.compute_client.get_windows_instance_initial_credentials(instance.id)
                attributes.append(Attribute("User", instance_credentials.data.username))
                attributes.append(Attribute("Password", instance_credentials.data.password))
            except (oci.exceptions.ServiceError, oci.exceptions.RequestException):
                attributes.append(Attribute("User", user))
                attributes.append(Attribute("Password", password))

            # set resource attributes (of the new resource) to use requested username and password

            vnic_attachments = self.compute_client.list_vnic_attachments(resource_config.compartment_ocid)

            vnic_attachment = next((vnic for vnic in vnic_attachments.data if vnic.instance_id == instance.id), None)
            if not vnic_attachment:
                raise Exception("No vnic")
            vnic_details = self.network_client.get_vnic(vnic_attachment.vnic_id)
            vnic_public_ip = vnic_details.data.public_ip

            if primary_vnic_action:
                primary_interface_json = json.dumps({
                    'interface_id': vnic_details.data.id,
                    'IP': vnic_details.data.private_ip,
                    'Public IP': vnic_public_ip,
                    'MAC Address': vnic_details.data.mac_address
                })
                network_results.append(ConnectToSubnetActionResult(actionId=primary_vnic_action.actionId,
                                                                   interface=primary_interface_json))

            if inbound_ports:
                new_security_list_item = self._add_security_list(compartment_ocid=resource_config.compartment_ocid,
                                                                 vcn_id=subnet.vcn_id,
                                                                 security_list_name=context.reservation.reservation_id,
                                                                 inbound_ports=inbound_ports,
                                                                 tags=self._get_tags(context))

                if new_security_list_item:
                    new_security_list = subnet.security_list_ids
                    new_security_list.append(new_security_list_item.data.id)
                    self.network_client_ops.update_subnet_and_wait_for_state(
                        subnet.id,
                        oci.core.models.UpdateSubnetDetails(security_list_ids=new_security_list),
                        [oci.core.models.Subnet.LIFECYCLE_STATE_AVAILABLE])

            instance_update = oci.core.models.UpdateInstanceDetails()
            instance_update.display_name = instance_name

            compute_client_composite_operations.update_instance_and_wait_for_state(
                instance.id,
                instance_update,
                wait_for_states=[oci.core.models.Instance.LIFECYCLE_STATE_RUNNING])

            for vnic_action in secondary_subnet_actions:
                secondary_vnic_details = CreateVnicDetails(assign_public_ip=vnic_action.actionParams.isPublic,
                                                           display_name=vnic_action.actionId,
                                                           subnet_id=vnic_action.actionParams.subnetId
                                                           )
                secondary_vnic_attach_details = AttachVnicDetails(create_vnic_details=secondary_vnic_details,
                                                                  display_name=vnic_action.actionId,
                                                                  instance_id=instance.id)
                result = compute_client_composite_operations.attach_vnic_and_wait_for_state(
                    secondary_vnic_attach_details,
                    [
                        oci.core.models.VnicAttachment.LIFECYCLE_STATE_ATTACHED
                    ])
                vnic_details = self.network_client.get_vnic(result.data.vnic_id)

                interface_json = json.dumps({
                    'interface_id': vnic_details.data.id,
                    'IP': vnic_details.data.private_ip,
                    'Public IP': vnic_details.data.public_ip,
                    'MAC Address': vnic_details.data.mac_address,
                })
                network_results.append(
                    ConnectToSubnetActionResult(actionId=vnic_action.actionId, interface=interface_json))

            deploy_result = DeployAppResult(actionId=deploy_action.actionId,
                                            infoMessage="Deployment Completed Successfully",
                                            vmUuid=instance.id,
                                            vmName=instance_name,
                                            deployedAppAddress=vnic_public_ip,
                                            deployedAppAttributes=attributes,
                                            vmDetailsData=self._create_vm_details(context, api, instance_name,
                                                                                  deploy_action.actionParams.deployment.deploymentPath,
                                                                                  instance.id))

            if cancellation_context.is_cancelled:
                termination_response = self.compute_client.terminate_instance(instance.id)
                while instance_details.data.lifecycle_state != "TERMINATED":
                    time.sleep(2)
                    instance_details = self.compute_client.get_instance(instance.id)
                return "deployment cancelled and deleted successfully"

            action_results = [deploy_result]
            action_results.extend(network_results)
            return action_results

    def ApplyConnectivityChanges(self, context, request):
        """
        Respond to CloudShell Server's request to apply L2 Connectivity changes 
        Implemented as empty implementation (always succeeds)
        :param context: ResourceCommandContext
        :param request: Changes to perform
        :return: 
        """
        api = CloudShellSessionContext(context).get_api()

        # Write request
        request_json = json.loads(request)

        # Build Response
        action_results = [
            {
                "actionId": str(actionResult['actionId']),
                "type": str(actionResult['type']),
                "infoMessage": "",
                "errorMessage": "",
                "success": "True",
                "updatedInterface": "None",
            } for actionResult in request_json['driverRequest']['actions']
        ]

        return self._set_command_result(str({"driverResponse": {"actionResults": action_results}}), False)

    def disconnect_all(self, context, ports):
        pass

    def disconnect(self, context, ports, network_name):
        pass

    def DeleteInstance(self, context, ports):
        """ Delete a VM
        :param context: ResourceRemoteCommandContext 
        :param ports: sub-resources to delete
        :return: 
        """

        # Code to delete instance based on remote command context
        resource_config = OCIShellDriverResource.create_from_context(context)
        self._connect_oracle_session(resource_config)
        instance_details = self.compute_client.get_instance(self._get_connected_instance_id(context))
        if instance_details is not None:
            termination_response = self.compute_client.terminate_instance(instance_details.data.id)
            while instance_details.data.lifecycle_state != "TERMINATED":
                time.sleep(2)
                instance_details = self.compute_client.get_instance(instance_details.data.id)
            return "Successfully terminated instance " + instance_details.data.id
        else:
            return "failed to terminate instance"

    def remote_refresh_ip(self, context, cancellation_context, ports):
        """ Refresh the IP of the resource from the VM
        :type context ResourceRemoteCommandContext
        """

        api = CloudShellSessionContext(context).get_api()
        address = ""
        resource_config = OCIShellDriverResource.create_from_context(context)

        self._connect_oracle_session(resource_config)
        instance_details = self.compute_client.get_instance(self._get_connected_instance_id(context))
        vnic_attachments = self.compute_client.list_vnic_attachments(
            resource_config.compartment_ocid)
        instance_vnic_attachment = next(
            vnic for vnic in vnic_attachments.data if vnic.instance_id == instance_details.data.id)
        vnic_details = self.network_client.get_vnic(instance_vnic_attachment.vnic_id)
        api.UpdateResourceAddress(context.remote_endpoints[0].fullname.split('/')[0], vnic_details.data.private_ip)
        try:
            api.SetAttributeValue(context.remote_endpoints[0].fullname.split('/')[0], "Public IP",
                                  vnic_details.data.public_ip)
        except:
            pass

        return address

    def PowerOff(self, context, ports):
        """ Power Off the VM represented by the resource
        :param context: ResourceRemoteCommandContext
        :param list[string] ports: the ports of the connection between the remote resource and the local resource, NOT IN USE!!!

        :type context ResourceRemoteCommandContext
        """

        api = CloudShellSessionContext(context).get_api()
        resource_config = OCIShellDriverResource.create_from_context(context)

        self._connect_oracle_session(resource_config)
        instance_id = self._get_connected_instance_id(context)
        instance_details = self.compute_client.get_instance(instance_id)
        if instance_details.data.lifecycle_state != "STOPPED":
            stop_response = self.compute_client.instance_action(instance_details.data.id, "stop")
            instance_details = self.compute_client.get_instance(instance_id)
            while instance_details.data.lifecycle_state != "STOPPED":
                time.sleep(2)
                instance_details = self.compute_client.get_instance(instance_id)

        try:
            api.SetResourceLiveStatus(context.remote_endpoints[0].fullname.split('/')[0], 'OCOffline',
                                      'Resource is powered off')
        except:  # if "OCOnline" live status is missing, revert to "Offline" live status
            api.SetResourceLiveStatus(context.remote_endpoints[0].fullname.split('/')[0], 'Offline',
                                      'Resource is powered off')

        return "VM stopped successfully"

    # the name is by the Qualisystems conventions
    def PowerOn(self, context, ports):
        """ Powers on the remote vm
        :param ResourceRemoteCommandContext context: the context the command runs on
        :param list[string] ports: the ports of the connection between the remote resource and the local resource, NOT IN USE!!!

        :type context ResourceRemoteCommandContext
        """
        api = CloudShellSessionContext(context).get_api()
        resource_config = OCIShellDriverResource.create_from_context(context)
        self._connect_oracle_session(resource_config)
        instance_id = self._get_connected_instance_id(context)
        instance_details = self.compute_client.get_instance(instance_id)
        if instance_details.data.lifecycle_state != "RUNNING":
            stop_response = self.compute_client.instance_action(instance_details.data.id, "start")
            instance_details = self.compute_client.get_instance(instance_id)
            while instance_details.data.lifecycle_state != "RUNNING":
                time.sleep(2)
                instance_details = self.compute_client.get_instance(instance_id)

        try:
            api.SetResourceLiveStatus(context.remote_endpoints[0].fullname.split('/')[0], 'OCOnline',
                                      'Resource is powered off')
        except:  # if "OCOnline" live status is missing, revert to "Offline" live status
            api.SetResourceLiveStatus(context.remote_endpoints[0].fullname.split('/')[0], 'Online',
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
        api = CloudShellSessionContext(context).get_api()
        output = self.PowerOff(context, ports)
        api.WriteMessageToReservationOutput(context.remote_reservation.reservation_id, output)
        time.sleep(float(delay))
        output = self.PowerOn(context, ports)
        api.WriteMessageToReservationOutput(context.remote_reservation.reservation_id, output)
        return

    def get_inventory(self, context):
        """
        :type context: models.QualiDriverModels.AutoLoadCommandContext
        """

        resource_config = OCIShellDriverResource.create_from_context(context)

        self._connect_oracle_session(resource_config)
        return AutoLoadDetails([], [])

    def get_vm_uuid(self, context, vm_name):
        """
        :param context: ResourceRemoteCommandContext 
        :param vm_name: full resource name of the resource
        :return: UID of the VM in OCI
        """
        api = CloudShellSessionContext(context).get_api()
        res_details = api.GetResourceDetails(vm_name)
        return str(jsonpickle.encode(res_details.VmDetails.UID, unpicklable=False))

    def GetVmDetails(self, context, cancellation_context, requests):
        """
        Return VM Details JSON to the Quali Server for refreshing the VM Details pane
        :param context: ResourceRemoteCommandContext
        :param cancellation_context: bool - will become True if action is cancelled
        :param requests: str JSON - requests for VMs to refresh 
        :return: 
        """

        api = CloudShellSessionContext(context).get_api()
        requests_json = json.loads(requests)
        vm_details_results = []
        for refresh_request in requests_json["items"]:
            vm_details_results.append(
                self._create_vm_details(context, api=api, vm_name=refresh_request["deployedAppJson"]["name"],
                                        deployment_service_name=refresh_request["appRequestJson"]["deploymentService"][
                                            "name"]))
        return str(jsonpickle.encode(vm_details_results, unpicklable=False))

    def _create_vm_details(self, context, api, vm_name, deployment_service_name, instance_id=None):
        """ Create the VM Details results used for both Deployment and Refresh VM Details
        :param context: 
        :param vm_name: 
        :param deployment_service_name: 
        :param instance_id: 
        :return: 
        """

        resource_config = OCIShellDriverResource.create_from_context(context)

        self._connect_oracle_session(resource_config)
        if not instance_id:
            res_details = api.GetResourceDetails(vm_name)
            instance_id = res_details.VmDetails.UID
        instance = self.compute_client.get_instance(instance_id)

        storage_attachments = self.compute_client.list_boot_volume_attachments(instance.data.availability_domain,
                                                                               instance.data.compartment_id)
        instance_volume = self.storage_client.get_boot_volume(
            next(x.boot_volume_id for x in storage_attachments.data if x.instance_id == instance.data.id))

        vm_instance_data = [
            VmDetailsProperty("Image ID", instance.data.image_id),
            VmDetailsProperty("VM Shape", instance.data.shape),
            VmDetailsProperty("Storage Name", instance_volume.data.id),
            VmDetailsProperty("Storage Size", str(instance_volume.data.size_in_gbs) + "GB"),
            VmDetailsProperty("Compartment ID", instance.data.compartment_id),
            VmDetailsProperty("Avilability Domain", instance.data.availability_domain)
        ]

        vm_network_data = []
        vnic_attachments = self.compute_client.list_vnic_attachments(instance.data.compartment_id)
        for vnic in vnic_attachments.data:
            if vnic.instance_id != instance_id:
                continue
            instance_nic = self.network_client.get_vnic(vnic.vnic_id)

            vm_nic = VmDetailsNetworkInterface()
            vm_nic.interfaceId = instance_nic.data.id
            vm_nic.networkId = instance_nic.data.subnet_id
            vm_nic.isPrimary = False
            vm_nic.isPredefined = False

            if vnic.display_name == context.reservation.reservation_id or vnic.display_name is None:
                vm_nic.isPrimary = True
                vm_nic.isPredefined = True
            vm_nic.privateIpAddress = instance_nic.data.private_ip
            vm_nic.networkData.append(VmDetailsProperty("IP", instance_nic.data.private_ip))
            vm_nic.networkData.append(VmDetailsProperty("Public IP", instance_nic.data.public_ip))
            vm_nic.networkData.append(VmDetailsProperty("MAC Address", instance_nic.data.mac_address))
            vm_nic.networkData.append(VmDetailsProperty("VLAN Name", vnic.vlan_tag))
            vm_network_data.append(vm_nic)
        return VmDetailsData(vm_instance_data, vm_network_data, vm_name)

    def console(self, context, ports, connection_type, client_os):
        """Generates a command for a console access to an instance"""
        win_ssh_link = "Start-Job {{ Echo N | plink.exe -i $env:homedrive$env:homepath\oci\console.ppk " \
                       "-N -ssh -P 443 -l {console_conn_id} -L {port1}:{instance_id}:{port2} {console_conn_endpoint} " \
                       "}}; sleep 5; plink.exe -i $env:homedrive$env:homepath\oci\console.ppk " \
                       "-P {port1} localhost -l {instance_id}"

        win_vnc_link = "Start-Job {{ Echo N | plink.exe -i $env:homedrive$env:homepath\oci\console.ppk " \
                       "-N -ssh -P 443 -l {console_conn_id} -L {port1}:{instance_id}:{port1} {console_conn_endpoint} " \
                       "}}; sleep 5; plink.exe -i $env:homedrive$env:homepath\oci\console.ppk " \
                       "-N -L {port2}:localhost:{port2} -P {port1} localhost -l {instance_id}"
        resource_config = OCIShellDriverResource.create_from_context(context)
        api = CloudShellSessionContext(context).get_api()
        self._connect_oracle_session(resource_config)
        compute_client_ops = oci.core.ComputeClientCompositeOperations(self.compute_client)

        with LoggingSessionContext(context) as logger:
            instance_id = self._get_connected_instance_id(context)
            keys_path = resource_config.keypairs_path
            if not keys_path.endswith("\\"):
                keys_path += "\\"
            ssh_pub_key_path = "{}{}.pub".format(keys_path, resource_config.default_keypair)
            ssh_pub_key = str(open(ssh_pub_key_path).read())
            create_console = oci.core.models.CreateInstanceConsoleConnectionDetails()
            create_console.freeform_tags = self._get_tags(context)
            create_console.instance_id = instance_id
            create_console.public_key = ssh_pub_key
            instance_console_ids = pagination.list_call_get_all_results(
                self.compute_client.list_instance_console_connections,
                resource_config.compartment_ocid,
                instance_id=instance_id
            )
            result = None
            instance_console_id = next((console_instance for console_instance in instance_console_ids.data), None)
            if instance_console_id:
                result = self.compute_client.get_instance_console_connection(instance_console_id.id)
            if not result:
                result = compute_client_ops.create_instance_console_connection_and_wait_for_state(
                    create_console,
                    wait_for_states=[oci.core.models.InstanceConsoleConnection.LIFECYCLE_STATE_ACTIVE])
            if "win" in client_os.lower():
                data_dict = {
                    "console_conn_id": result.data.id,
                    "console_conn_endpoint": "instance-console.{}.oraclecloud.com".format(resource_config.region),
                    "port1": 5905,
                    "port2": 5900,
                    "instance_id": instance_id
                }
                pattern = r"^.*{}@(?P<console_conn_endpoint>\S+)'".format(result.data.id)
                endpoint_string_match = re.search(pattern, result.data.vnc_connection_string, re.IGNORECASE)
                if endpoint_string_match:
                    data_dict.update(endpoint_string_match.groupdict())
                if "vnc" in connection_type.lower():
                    response = win_vnc_link.format(**data_dict)
                else:
                    data_dict["port1"] = 22000
                    data_dict["port2"] = 22
                    response = win_ssh_link.format(**data_dict)
            else:
                response = result.data.connection_string
                if "vnc" in connection_type.lower():
                    response = result.data.vnc_connection_string

            api.WriteMessageToReservationOutput(context.remote_reservation.reservation_id,
                                                "Console link is: {}".format(response))

    def _remote_save_snapshot(self, context, ports, snapshot_name):
        resource_config = OCIShellDriverResource.create_from_context(context)
        self._connect_oracle_session(resource_config)

        with LoggingSessionContext(context) as logger:
            instance_id = self._get_connected_instance_id(context)
            instance = self.compute_client.get_instance(instance_id)
            boot_volumes = self.compute_client.list_boot_volume_attachments(instance.data.availability_domain,
                                                                            instance.data.compartment_id,
                                                                            instance_id=instance_id)

            tags = self._get_tags(context)
            tags["InstanceId"] = instance_id
            for instance_volume in boot_volumes.data:
                if instance_volume.instance_id == instance_id:
                    backup_details = oci.core.models.CreateBootVolumeBackupDetails(
                        boot_volume_id=instance_volume.boot_volume_id,
                        display_name=snapshot_name,
                        freeform_tags=tags,
                        type="FULL"
                    )
                    self.storage_client_ops.create_boot_volume_backup_and_wait_for_state(
                        backup_details,
                        [oci.core.models.BootVolumeBackup.LIFECYCLE_STATE_AVAILABLE])
            return "Backup {} created successfully".format(snapshot_name)

    def _remote_get_snapshots(self, context, ports):
        resource_config = OCIShellDriverResource.create_from_context(context)
        self._connect_oracle_session(resource_config)

        with LoggingSessionContext(context) as logger:
            instance_id = self._get_connected_instance_id(context)
            instance = self.compute_client.get_instance(instance_id)
            volume_backups = self.storage_client.list_boot_volume_backups(instance.data.compartment_id)
            return [backup.display_name for backup in volume_backups.data if
                    backup.freeform_tags["InstanceId"] == instance_id]

    def _remote_restore_snapshot(self, context, ports, snapshot_name):
        # ToDo for future implementation
        resource_config = OCIShellDriverResource.create_from_context(context)
        self._connect_oracle_session(resource_config)

        with LoggingSessionContext(context) as logger:
            self.PowerOff(context, ports)



    def PrepareSandboxInfra(self, context, request, cancellation_context):
        """
        Called by CloudShell Orchestration during the Setup process in order to populate information about the networking environment used by the sandbox
        :param context: ResourceRemoteCommandContext 
        :param request: Actions to be performed to prepare the networking environment sent by CloudShell Server
        :param cancellation_context: 
        :return: 
        """

        with LoggingSessionContext(context) as logger:
            api = CloudShellSessionContext(context).get_api()
            resource_config = OCIShellDriverResource.create_from_context(context)

            # api.WriteMessageToReservationOutput(context.reservation.reservation_id, 'Request JSON: ' + request)
            self._connect_oracle_session(resource_config)
            json_request = json.loads(request)
            api.WriteMessageToReservationOutput(context.reservation.reservation_id, 'Preparing Sandbox Connectivity...')

            vcn_cidr = ""
            keys_action_id = ""
            vcn_action_id = ""
            subnet_dict = {}
            subnet_results = []
            virtual_network_client = VirtualNetworkClientCompositeOperations(self.network_client)

            for action in json_request["driverRequest"]["actions"]:
                if action["type"] == "prepareCloudInfra":
                    vcn_cidr = action.get("actionParams", {}).get("cidr", )
                    vcn_action_id = action.get("actionId")
                elif action["type"] == "prepareSubnet":
                    subnet_cidr = action.get("actionParams", {}).get("cidr", )
                    subnet_action_id = action.get("actionId")
                    subnet_dict[subnet_action_id] = subnet_cidr
                if action["type"] == "createKeys":
                    keys_action_id = action.get("actionId")

            list_availability_domains_response = oci.pagination.list_call_get_all_results(
                self.identity_client.list_availability_domains,
                resource_config.compartment_ocid
            )
            availability_domain = list_availability_domains_response.data[0].name
            tags_to_add = self._get_tags(context)

            if vcn_cidr:
                prepare_network_result = PrepareCloudInfraResult(vcn_action_id)
                vcn = self._get_unique_vcn_by_name(resource_config.compartment_ocid, context.reservation.reservation_id)

                if not vcn:
                    new_vcn = virtual_network_client.create_vcn_and_wait_for_state(
                        oci.core.models.CreateVcnDetails(
                            cidr_block=vcn_cidr,
                            display_name=context.reservation.reservation_id,
                            freeform_tags=tags_to_add,
                            compartment_id=resource_config.compartment_ocid
                        ),
                        [oci.core.models.Vcn.LIFECYCLE_STATE_AVAILABLE]
                    )
                    vcn = new_vcn.data
                    default_route_table = self.network_client.get_route_table(vcn.default_route_table_id)
                    route_rules = default_route_table.data.route_rules
                    inet_gw = virtual_network_client.create_internet_gateway_and_wait_for_state(
                        oci.core.models.CreateInternetGatewayDetails(
                            vcn_id=vcn.id,
                            display_name=context.reservation.reservation_id,
                            freeform_tags=tags_to_add,
                            is_enabled=True,
                            compartment_id=resource_config.compartment_ocid),
                        [oci.core.models.InternetGateway.LIFECYCLE_STATE_AVAILABLE]
                    )
                    default_static_rule = oci.core.models.RouteRule(
                        cidr_block=None,
                        destination=self.STATIC_CIDR,
                        destination_type='CIDR_BLOCK',
                        network_entity_id=inet_gw.data.id
                    )
                    route_rules.append(default_static_rule)
                    update_route_table_details = oci.core.models.UpdateRouteTableDetails(route_rules=route_rules,
                                                                                         freeform_tags=tags_to_add)
                    virtual_network_client.update_route_table_and_wait_for_state(
                        vcn.default_route_table_id,
                        update_route_table_details,
                        wait_for_states=[oci.core.models.RouteTable.LIFECYCLE_STATE_AVAILABLE]
                    )
                vcn_ocid = vcn.id
                prepare_network_result.securityGroupId = vcn.default_security_list_id
                if not vcn_ocid:
                    raise Exception("Failed to create VCN")
                for action_id in subnet_dict:
                    subnet_cidr = subnet_dict.get(action_id)
                    subnet = self._get_unique_subnet_by_cidr(resource_config.compartment_ocid, vcn_id=vcn_ocid,
                                                             subnet_cidr=subnet_cidr)
                    # ToDo if vcn was just created there is no need to check for subnets
                    if not subnet:
                        new_subnet = virtual_network_client.create_subnet_and_wait_for_state(
                            oci.core.models.CreateSubnetDetails(
                                compartment_id=resource_config.compartment_ocid,
                                availability_domain=availability_domain,
                                freeform_tags=tags_to_add,
                                display_name=action_id,
                                vcn_id=vcn_ocid,
                                cidr_block=subnet_dict.get(action_id)
                            ),
                            [oci.core.models.Subnet.LIFECYCLE_STATE_AVAILABLE]
                        )
                        subnet = new_subnet.data
                    subnet_result = PrepareSubnetActionResult()
                    subnet_result.actionId = action_id
                    subnet_result.subnetId = subnet.id
                    subnet_result.infoMessage = "Success"
                    subnet_results.append(subnet_result)

            prepare_network_result.infoMessage = 'PrepareConnectivity finished successfully'

            # Set Security Group
            # subnet_info = self.network_client.get_subnet(subnet_cidr_ocid)
            # prepare_network_result.securityGroupId = subnet_info.data.security_list_ids[0]

            # Set VPC ID
            prepare_network_result.networkId = vcn_ocid

            # Set Keypair ToDo generate ssh keys
            keypair_path = "{}\\{}".format(resource_config.keypairs_path, resource_config.default_keypair)
            # api.WriteMessageToReservationOutput(context.reservation.reservation_id, 'Reading Sandbox Keypair {0}...')
            create_key_result = CreateKeysActionResult(actionId=keys_action_id, infoMessage='',
                                                       accessKey=str(open(keypair_path).read()))

            results = [prepare_network_result, create_key_result]
            results.extend(subnet_results)

            result = DriverResponse(results).to_driver_response_json()
            # api.WriteMessageToReservationOutput(context.reservation.reservation_id,
            #                                     'Prepare Sandbox Response: {}'.format(result))
            return result

    def CleanupSandboxInfra(self, context, request):
        """
        
        :param context: 
        :param request: 
        :return: 
        """
        api = CloudShellSessionContext(context).get_api()
        # api.WriteMessageToReservationOutput(context.reservation.reservation_id, 'Cleanup Request JSON: ' + request)
        json_request = json.loads(request)
        resource_config = OCIShellDriverResource.create_from_context(context)
        self._connect_oracle_session(resource_config)
        cleanup_action_id = next(action["actionId"] for action in json_request["driverRequest"]["actions"] if
                                 action["type"] == "cleanupNetwork")

        vcn = self._get_unique_vcn_by_name(resource_config.compartment_ocid, context.reservation.reservation_id)
        if vcn:
            subnets = self._get_unique_subnet_by_cidr(resource_config.compartment_ocid, vcn_id=vcn.id) or []
            service_gateways = self._get_service_gateways(resource_config.compartment_ocid, vcn_id=vcn.id) or []
            internet_gateways = self._get_inet_gateways(resource_config.compartment_ocid, vcn_id=vcn.id) or []
            for subnet in subnets:
                self.network_client_ops.delete_subnet_and_wait_for_state(
                    subnet.id,
                    [oci.core.models.Subnet.LIFECYCLE_STATE_TERMINATED])
            default_route_table = self.network_client.get_route_table(vcn.default_route_table_id)
            route_rules = default_route_table.data.route_rules
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
            security_lists = self.network_client.list_security_lists(resource_config.compartment_ocid, vcn.id)
            for list in security_lists.data:
                if list.time_created == vcn.time_created:  # and "default" in list.display_name.lower():
                    continue
                self.network_client_ops.delete_security_list_and_wait_for_state(
                    list.id,
                    [oci.core.models.SecurityList.LIFECYCLE_STATE_TERMINATED])
            for internet_gw in internet_gateways:
                self.network_client_ops.delete_internet_gateway_and_wait_for_state(
                    internet_gw.id,
                    wait_for_states=[oci.core.models.InternetGateway.LIFECYCLE_STATE_TERMINATED]
                )

            self.network_client_ops.delete_vcn_and_wait_for_state(
                vcn.id,
                [oci.core.models.Vcn.LIFECYCLE_STATE_TERMINATED])

        cleanup_result = ActionResultBase("cleanupNetwork", cleanup_action_id)

        return self._set_command_result({'driverResponse': {'actionResults': [cleanup_result]}})

    def _get_unique_vcn_by_name(self, compartment_id, display_name):
        """
        Find a unique Vcn by name.
        :param compartment_id: The OCID of the compartment which owns the Vcn.
        :type compartment_id: str
        :param display_name: The display name of the Vcn.
        :type display_name: str
        :return: The Vcn
        :rtype: core_models.Vcn
        """

        result = pagination.list_call_get_all_results(
            self.network_client.list_vcns,
            compartment_id,
            display_name=display_name
        )
        for vcn in result.data:
            if display_name == vcn.display_name:
                return vcn

    def _get_unique_subnet_by_cidr(self, compartment_id, vcn_id, subnet_cidr=None):
        """
        Find a unique Subnet by name.
        :param compartment_id: The OCID of the compartment which owns the VCN.
        :type compartment_id: str
        :param vcn_id: The OCID of the VCN which will own the subnet.
        :type vcn_id: str
        :param subnet_cidr: Subnet CIDR.
        :type subnet_cidr: str
        :return: The Subnet
        :rtype: core_models.Subnet
        """
        result = pagination.list_call_get_all_results(
            self.network_client.list_subnets,
            compartment_id,
            vcn_id
        )

        print result
        if not subnet_cidr and result.data:
            return result.data
        for item in result.data:
            if subnet_cidr == item.cidr_block:
                return item

    def _get_service_gateways(self, compartment_id, vcn_id):
        """
        Find a unique Subnet by name.
        :param compartment_id: The OCID of the compartment which owns the VCN.
        :type compartment_id: str
        :param vcn_id: The OCID of the VCN which will own the subnet.
        :type vcn_id: str
        :return: The Subnet
        :rtype: core_models.Subnet
        """
        result = pagination.list_call_get_all_results(
            self.network_client.list_service_gateways,
            compartment_id,
            vcn_id=vcn_id
        )

        return result.data

    def _get_inet_gateways(self, compartment_id, vcn_id):
        """
        Find a unique Subnet by name.
        :param compartment_id: The OCID of the compartment which owns the VCN.
        :type compartment_id: str
        :param vcn_id: The OCID of the VCN which will own the subnet.
        :type vcn_id: str
        :return: The Subnet
        :rtype: core_models.Subnet
        """
        result = pagination.list_call_get_all_results(
            self.network_client.list_internet_gateways,
            compartment_id,
            vcn_id=vcn_id
        )

        return result.data

    def _get_tags(self, context):
        if hasattr(context, "remote_reservation"):
            reservation = context.remote_reservation
        else:
            reservation = context.reservation
        return {
            "CreatedBy": "Cloudshell",
            "ReservationId": reservation.reservation_id,
            "Owner": reservation.owner_user,
            "Domain": reservation.domain,
            "Blueprint": reservation.environment_name
        }

    def _add_security_list(self, vcn_id, security_list_name, compartment_ocid, tags, inbound_ports):
        inbound_ports_map = {
            "tcp": oci.core.models.TcpOptions,
            "icmp": oci.core.models.IcmpOptions,
            "udp": oci.core.models.UdpOptions
        }
        inbound_ports_protocol_map = {"icmp": "1", "tcp": "6", "udp": "17", "icmpv6": "58"}
        security_list_ingress_rules = []
        inbound_ports_list = inbound_ports.split(";")
        for port in inbound_ports_list:
            protocol = "tcp"
            if ":" in port:
                port_data = port.split(":")
                protocol = port_data[1]
                ports = port_data[0].replace(" ", "")
            else:
                ports = port
            rule_type = inbound_ports_map.get(protocol)
            if rule_type:
                rules_to_add_list = ports.split(",")
                for rule_ports in rules_to_add_list:
                    try:
                        if "-" in rule_ports:
                            rule_ports_list = map(int, rule_ports.split("-"))
                            min_port = min(rule_ports_list)
                            max_port = max(rules_to_add_list)
                            port_range = oci.core.models.PortRange(min=min_port, max_port=max_port)
                        else:
                            port_range = oci.core.models.PortRange(min=int(rule_ports), max=int(rule_ports))
                    except:
                        continue
                    rule_parameters = {
                        "protocol": inbound_ports_protocol_map.get(protocol),
                        "source": self.STATIC_CIDR,
                        "{}_options".format(protocol): rule_type(destination_port_range=port_range)
                    }
                    security_list_ingress_rules.append(oci.core.models.IngressSecurityRule(**rule_parameters))

        if security_list_ingress_rules:
            return self.network_client_ops.create_security_list_and_wait_for_state(
                oci.core.models.CreateSecurityListDetails(
                    vcn_id=vcn_id,
                    display_name=security_list_name,
                    freeform_tags=tags,
                    compartment_id=compartment_ocid,
                    ingress_security_rules=security_list_ingress_rules,
                    egress_security_rules=[oci.core.models.EgressSecurityRule(destination=self.STATIC_CIDR,
                                                                              protocol="all")]
                ),
                [oci.core.models.SecurityList.LIFECYCLE_STATE_AVAILABLE]
            )
