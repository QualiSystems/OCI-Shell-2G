
from copy import copy

import time
import json
import jsonpickle
import oci

from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.driver_context import AutoLoadDetails

from cloudshell.cp.core import DriverRequestParser
from cloudshell.cp.core.models import DeployApp, DeployAppResult, DriverResponse, VmDetailsData, VmDetailsProperty, \
    VmDetailsNetworkInterface, Attribute, ConnectSubnet
from cloudshell.cp.core.models import PrepareCloudInfraResult, CreateKeysActionResult, ActionResultBase

from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.session.logging_session import LoggingSessionContext
from oci import pagination
from oci.core import VirtualNetworkClientCompositeOperations
from oci.core.models import AttachVnicDetails, CreateVnicDetails

from data_model import OCIShellDriverResource


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

    def _get_connected_instance_id(self, context):
        """ Retrieve UID of the VM the resource represents
        :param context: 
        :return: 
        """

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
        api.WriteMessageToReservationOutput(context.reservation.reservation_id, 'Request JSON: ' + request)

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
                deploy_result = deploy_method(context, api, deploy_action, subnet_actions, cancellation_context)
                return DriverResponse([deploy_result]).to_driver_response_json()
            except StopIteration:
                raise Exception('Could not find the deployment ' + deployment_name)
        else:
            raise Exception('Failed to deploy VM')

    def vm_from_image(self, context, api, deploy_action, subnet_actions, cancellation_context):
        """
        :type subnet_actions: list<ConnectSubnet>
        """

        # Init CloudShell and OCI APIs
        with LoggingSessionContext(context) as logger:

            resource_config = OCIShellDriverResource.create_from_context(context)
            self._connect_oracle_session(resource_config)
            secondary_subnet_actions = {}
            # Read deployment attributes
            app_name = deploy_action.actionParams.appName
            deploy_attribs = deploy_action.actionParams.deployment.attributes
            vcn = self._get_unique_vcn_by_name(resource_config.compartment_ocid, context.reservation.reservation_id)
            subnets = self._get_unique_subnet_by_cidr(resource_config.compartment_ocid, vcn_id=vcn.id)
            subnet = subnets[0]
            subnet_id = subnet.id
            vnic_id = context.reservation.reservation_id
            if subnet_actions:
                subnet_actions.sort(key=lambda x: x.actionParams.vnicName)
                primary_vnic_action = subnet_actions[0]
                primary_vnic0_action = next(
                    action for action in subnet_actions if action.actionParams.vnicName == "0")
                if primary_vnic0_action:
                    primary_vnic_action = primary_vnic0_action

                secondary_subnet_actions = copy(subnet_actions)
                secondary_subnet_actions.remove(primary_vnic_action)

                subnet_id = primary_vnic_action.actionParams.subnetId
                subnet = next(s for s in subnets if s.id == subnet_id)

            availability_domain = subnet.availability_domain

            image_id = self._get_val_by_key_suffix(deploy_attribs, "Image ID")
            public_ip_str = self._get_val_by_key_suffix(deploy_attribs, "Public IP")
            public_ip = public_ip_str.lower() == "true"
            vm_shape = self._get_val_by_key_suffix(deploy_attribs, "VM Shape")
            try:
                user = self._get_val_by_key_suffix(deploy_attribs, "User")
            except:
                user = ""
            try:
                password = self._get_val_by_key_suffix(deploy_attribs, "Password")
            except:
                password = ""

            keys_path = resource_config.keypairs_path
            if not keys_path.endswith("\\"):
                keys_path += "\\"
            ssh_pub_key_path = "{}{}.pub".format(keys_path, resource_config.default_keypair)
            default_ssh_pub_key = str(open(ssh_pub_key_path).read())
            ssh_pub_key = default_ssh_pub_key
            # ssh_pub_key = self.reservation_to_ssh_keys_map.get(context.reservation.reservation_id,
            #                                                    default_ssh_pub_key)

            new_inst_details = oci.core.models.LaunchInstanceDetails()
            # CreateVnicDetails
            new_inst_details.availability_domain = availability_domain
            new_inst_details.compartment_id = resource_config.compartment_ocid
            new_inst_details.subnet_id = subnet_id
            new_inst_details.display_name = app_name
            new_inst_details.create_vnic_details = CreateVnicDetails(assign_public_ip=public_ip,
                                                                     display_name=vnic_id,
                                                                     subnet_id=subnet_id
                                                                     )
            new_inst_details.shape = vm_shape
            new_inst_details.image_id = image_id
            new_inst_details.metadata = {
                'ssh_authorized_keys': ssh_pub_key
            }

            # Create the VM
            # DEBUG
            # api.WriteMessageToReservationOutput(context.reservation.reservation_id,
            #                                     "Launching Instance of shape {0} of image {1} in AD {2} Subnet {3}".
            #                                     format(new_inst_details.shape, new_inst_details.image_id, new_inst_details.availability_domain, new_inst_details.subnet_id))
            launch_instance_result = self.compute_client.launch_instance(new_inst_details)

            instance_details = self.compute_client.get_instance(launch_instance_result.data.id)
            instance_name = app_name + " " + launch_instance_result.data.id.split(".")[-1][-10:]

            # Wait for "Running" Status
            wait_time = 0
            while instance_details.data.lifecycle_state != "RUNNING" and wait_time <= 600:
                time.sleep(2)
                wait_time = wait_time + 2
                instance_details = self.compute_client.get_instance(launch_instance_result.data.id)

            if wait_time > 600:
                termination_response = self.compute_client.terminate_instance(instance_details.data.id)
                raise RuntimeError("Timeout when waiting for VM to Power on")

            # If windows instance, wait for "Ok" Status
            # app_details = None
            app_details = next(
                app for app in api.GetReservationDetails(context.reservation.reservation_id).ReservationDescription.Apps
                if app.Name == app_name)
            try:
                app_os = next(att.Value for att in app_details.LogicalResource.Attributes if
                              att.Name in ["OS", "Operating System"])
            except:
                app_os = ""

            attributes = []

            if "windows" in app_os.lower() and (password == "" or api.DecryptPassword(password).Value == ""):
                instance_credentials = self.compute_client.get_windows_instance_initial_credentials(
                    launch_instance_result.data.id)
                attributes.append(Attribute("User", instance_credentials.data.username))
                attributes.append(Attribute("Password", instance_credentials.data.password))
            elif user:
                attributes.append(Attribute("User", user))
                attributes.append(Attribute("Password", password))

            # set resource attributes (of the new resource) to use requested username and password

            vnic_attachments = self.compute_client.list_vnic_attachments(resource_config.compartment_ocid)
            instance_vnic_attachment = next(
                vnic for vnic in vnic_attachments.data if vnic.instance_id == launch_instance_result.data.id)
            vnic_details = self.network_client.get_vnic(instance_vnic_attachment.vnic_id)

            instace_update = oci.core.models.UpdateInstanceDetails()
            instace_update.display_name = instance_name

            self.compute_client.update_instance(instance_details.data.id, instace_update)

            for vnic_action in secondary_subnet_actions:
                secondary_vnic_details = CreateVnicDetails(assign_public_ip=vnic_action.actionParams.isPublic,
                                                           display_name=vnic_action.actionId,
                                                           subnet_id=vnic_action.actionParams.subnetId
                                                           )
                secondary_vnic_attach_details = AttachVnicDetails(create_vnic_details=secondary_vnic_details,
                                                                  display_name=vnic_action.actionId,
                                                                  instance_id=launch_instance_result.data.id)
                self.compute_client.attach_vnic(secondary_vnic_attach_details)

            deploy_result = DeployAppResult(actionId=deploy_action.actionId,
                                            infoMessage="Deployment Completed Successfully",
                                            vmUuid=instance_details.data.id,
                                            vmName=instance_name,
                                            deployedAppAddress=vnic_details.data.public_ip,
                                            deployedAppAttributes=attributes,
                                            vmDetailsData=self._create_vm_details(context, instance_name,
                                                                                  deploy_action.actionParams.deployment.deploymentPath,
                                                                                  launch_instance_result.data.id))

            if cancellation_context.is_cancelled:
                termination_response = self.compute_client.terminate_instance(instance_details.data.id)
                while instance_details.data.lifecycle_state != "TERMINATED":
                    time.sleep(2)
                    instance_details = self.compute_client.get_instance(launch_instance_result.data.id)
                return "deployment cancelled and deleted successfully"

            return deploy_result

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
        requests_json = json.loads(requests)
        vm_details_results = []
        for refresh_request in requests_json["items"]:
            vm_details_results.append(
                self._create_vm_details(context, vm_name=refresh_request["deployedAppJson"]["name"],
                                        deployment_service_name=refresh_request["appRequestJson"]["deploymentService"][
                                            "name"]))
        return str(jsonpickle.encode(vm_details_results, unpicklable=False))

    def _create_vm_details(self, context, vm_name, deployment_service_name, instance_id=None):
        """ Create the VM Details results used for both Deployment and Refresh VM Details
        :param context: 
        :param vm_name: 
        :param deployment_service_name: 
        :param instance_id: 
        :return: 
        """
        api = CloudShellSessionContext(context).get_api()
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

        vnic_attachments = self.compute_client.list_vnic_attachments(instance.data.compartment_id)
        instance_nic = self.network_client.get_vnic(
            next(x.vnic_id for x in vnic_attachments.data if x.instance_id == instance.data.id))

        vm_instance_data = []
        vm_instance_data.append(VmDetailsProperty("Image ID", instance.data.image_id))
        vm_instance_data.append(VmDetailsProperty("VM Shape", instance.data.shape))
        vm_instance_data.append(VmDetailsProperty("Storage Name", instance_volume.data.id))
        vm_instance_data.append(VmDetailsProperty("Storage Size", str(instance_volume.data.size_in_gbs) + "GB"))
        vm_instance_data.append(VmDetailsProperty("Compartment ID", instance.data.compartment_id))
        vm_instance_data.append(VmDetailsProperty("Avilability Domain", instance.data.availability_domain))

        vm_nic = VmDetailsNetworkInterface()
        vm_nic.interfaceId = instance_nic.data.id
        vm_nic.networkId = instance_nic.data.subnet_id
        vm_nic.isPrimary = True
        vm_nic.isPredefined = True
        vm_nic.privateIpAddress = instance_nic.data.private_ip
        vm_nic.networkData.append(VmDetailsProperty("IP", instance_nic.data.private_ip))
        vm_nic.networkData.append(VmDetailsProperty("Public IP", instance_nic.data.public_ip))
        vm_nic.networkData.append(VmDetailsProperty("MAC Address", instance_nic.data.mac_address))
        vm_nic.networkData.append(VmDetailsProperty("VLAN Name",
                                                    "Default Subnet" if "Default" in deployment_service_name else "Custom Subnet"))
        vm_network_data = [vm_nic]
        return VmDetailsData(vm_instance_data, vm_network_data, vm_name)

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

            if vcn_cidr:
                prepare_network_result = PrepareCloudInfraResult(vcn_action_id)
                vcn = self._get_unique_vcn_by_name(resource_config.compartment_ocid, context.reservation.reservation_id)

                if not vcn:
                    new_vcn = virtual_network_client.create_vcn_and_wait_for_state(
                        oci.core.models.CreateVcnDetails(
                            cidr_block=vcn_cidr,
                            display_name=context.reservation.reservation_id,
                            compartment_id=resource_config.compartment_ocid
                        ),
                        [oci.core.models.Vcn.LIFECYCLE_STATE_AVAILABLE]
                    )
                    vcn = new_vcn.data
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
                                display_name=action_id,
                                vcn_id=vcn_ocid,
                                cidr_block=subnet_dict.get(action_id)
                            ),
                            [oci.core.models.Subnet.LIFECYCLE_STATE_AVAILABLE]
                        )
                        subnet = new_subnet.data
                    subnet_result = PrepareCloudInfraResult()
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
            keypair_path = "{}\\{}.ppk".format(resource_config.keypairs_path, resource_config.default_keypair)
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
        # DEBUG    api.WriteMessageToReservationOutput(context.reservation.reservation_id, 'Cleanup Request JSON: ' + request)
        json_request = json.loads(request)
        resource_config = OCIShellDriverResource.create_from_context(context)
        virt_net_client = VirtualNetworkClientCompositeOperations(self.network_client)

        cleanup_action_id = next(action["actionId"] for action in json_request["driverRequest"]["actions"] if
                                 action["type"] == "cleanupNetwork")

        vcn = self._get_unique_vcn_by_name(resource_config.compartment_ocid, context.reservation.reservation_id)
        subnets = self._get_unique_subnet_by_cidr(resource_config.compartment_ocid, vcn_id=vcn)
        service_gateways = self._get_vcn_service_gateways(resource_config.compartment_ocid, vcn_id=vcn)
        for subnet in subnets:
            virt_net_client.delete_subnet_and_wait_for_state(subnet.id,
                                                             [oci.core.models.Subnet.LIFECYCLE_STATE_TERMINATED])
        for service_gw in service_gateways:
            virt_net_client.delete_service_gateway_and_wait_for_state(
                service_gw.id,
                [oci.core.models.ServiceGateway.LIFECYCLE_STATE_TERMINATED]
            )
        virt_net_client.delete_vcn_and_wait_for_state(vcn.id,
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

    def _get_vcn_service_gateways(self, compartment_id, vcn_id):
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
            vcn_id
        )

        return result.data
