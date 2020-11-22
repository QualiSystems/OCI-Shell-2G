import base64
import time

import oci
from oci import pagination
from oci.exceptions import CompositeOperationError, ServiceError

from cs_oci.helper.shell_helper import OciShellError, RETRY_STRATEGY


class OciComputeOps(object):
    VNIC_ATTACHMENT_RETRY = 3
    VNIC_ATTACHMENT_TIMEOUT = 2
    MAX_INSTANCE_WAIT_TIMEOUT = 1600
    INSTANCE_START = "START"
    INSTANCE_STOP = "STOP"
    _INSTANCE_STATE_MAP = {INSTANCE_START: oci.core.models.Instance.LIFECYCLE_STATE_RUNNING,
                           INSTANCE_STOP: oci.core.models.Instance.LIFECYCLE_STATE_STOPPED}

    def __init__(self, resource_config, logger):
        """

        :type resource_config: src.data_model.OCIShellDriverResource
        """
        config = resource_config.oci_config
        self._logger = logger
        self.resource_config = resource_config
        self.compute_client = oci.core.ComputeClient(config, retry_strategy=RETRY_STRATEGY)
        self.compute_client_ops = oci.core.ComputeClientCompositeOperations(self.compute_client)

    def change_instance_state(self, instance_id, new_state):
        instance = self.compute_client.get_instance(instance_id)
        instance_state = self._INSTANCE_STATE_MAP.get(new_state)
        if instance.data and instance.data.lifecycle_state != instance_state:
            self.compute_client_ops.instance_action_and_wait_for_state(
                instance_id,
                new_state,
                [instance_state]
            )

    def launch_instance(self, app_name,
                        vm_details,
                        ssh_pub_key,
                        timeout=MAX_INSTANCE_WAIT_TIMEOUT):

        compatible_shapes = pagination.list_call_get_all_results(self.compute_client.list_shapes,
                                                                 compartment_id=self.resource_config.compartment_ocid,
                                                                 availability_domain=vm_details.availability_domain,
                                                                 image_id=vm_details.image_id)
        is_shape_compatible = next((x.shape for x in compatible_shapes.data if x.shape == vm_details.vm_shape), None)
        if not is_shape_compatible:
            raise OciShellError("Incompatible shape chosen for deployment on App {}. "
                                "Please check the available shapes for this image on OCI".format(app_name))

        new_inst_details = oci.core.models.LaunchInstanceDetails()
        # Create LaunchInstanceDetails
        new_inst_details.availability_domain = vm_details.availability_domain
        new_inst_details.compartment_id = self.resource_config.compartment_ocid
        new_inst_details.subnet_id = vm_details.primary_subnet.subnet_id
        new_inst_details.display_name = app_name
        new_inst_details.freeform_tags = self.resource_config.tags
        vnic_name = "{} Primary Vnic".format(app_name)
        if vm_details.primary_subnet.private_ip:
            vnic_name = vm_details.primary_subnet.private_ip.name or vnic_name
        new_inst_details.create_vnic_details = oci.core.models.CreateVnicDetails(
            assign_public_ip=vm_details.public_ip,
            display_name=vnic_name,
            skip_source_dest_check=vm_details.skip_src_dst_check,
            subnet_id=vm_details.primary_subnet.subnet_id)
        if vm_details.primary_subnet.private_ip and vm_details.primary_subnet.private_ip.ip:
            new_inst_details.create_vnic_details.private_ip = vm_details.primary_subnet.private_ip.ip
        new_inst_details.shape = vm_details.vm_shape
        new_inst_details.image_id = vm_details.image_id
        new_inst_details.metadata = {"ssh_authorized_keys": ssh_pub_key}
        if vm_details.cloud_init_params:
            data = vm_details.cloud_init_params
            try:
                with open(vm_details.cloud_init_params, 'rb+') as script:
                    data = script.read()
            except IOError:
                pass
            new_inst_details.metadata["user_data"] = base64.b64encode(data.decode('string_escape'))

        wait_for_states = [oci.core.models.Instance.LIFECYCLE_STATE_RUNNING]
        # Start the VM
        try:
            launch_instance_response = self.compute_client_ops.launch_instance_and_wait_for_state(
                new_inst_details,
                wait_for_states=wait_for_states)
            return launch_instance_response.data
        except CompositeOperationError as e:
            deployed_instance = next(i.data for i in e.partial_results if i.data.display_name == app_name)
            self._logger.error("Failed to launch instance {}".format(deployed_instance.display_name))
            instance = self.compute_client.get_instance(deployed_instance.id)
            if instance.data.lifecycle_state == oci.core.models.Instance.LIFECYCLE_STATE_RUNNING:
                return instance.data
            elif instance.data.lifecycle_state == oci.core.models.Instance.LIFECYCLE_STATE_STARTING:
                try:
                    waiter_result = oci.wait_until(
                        self.compute_client,
                        self.compute_client.get_instance(instance.data.id),
                        evaluate_response=lambda r: getattr(r.data, 'lifecycle_state')
                                                    and getattr(r.data, 'lifecycle_state').lower()
                                                    in [w.lower() for w in wait_for_states],
                        **{}
                    )
                    result_to_return = waiter_result
                    return result_to_return.data
                except Exception as e:
                    pass
            self.terminate_instance(instance.data.id)
            raise OciShellError("Timeout exceeded when waiting for VM to Deploy")

    def get_windows_credentials(self, instance_id):
        try:
            instance_credentials = self.compute_client.get_windows_instance_initial_credentials(instance_id)
            user = instance_credentials.data.username
            password = instance_credentials.data.password
            return user, password
        except (oci.exceptions.ServiceError, oci.exceptions.RequestException):
            pass

    def get_vnic_attachments(self, instance_id):
        """

        :param instance_id:
        :return: list[oci]
        :rtype: list[oci.core.models.VnicAttachment]
        """
        vnic_attachments = self.compute_client.list_vnic_attachments(self.resource_config.compartment_ocid)
        return [vnic for vnic in vnic_attachments.data if vnic.instance_id == instance_id]

    def update_instance_name(self, name, instance_id):
        instance_update = oci.core.models.UpdateInstanceDetails()
        instance_update.display_name = name

        self.compute_client_ops.update_instance_and_wait_for_state(
            instance_id,
            instance_update,
            wait_for_states=[oci.core.models.Instance.LIFECYCLE_STATE_RUNNING])

    def terminate_instance(self, instance_id=None):
        if not instance_id:
            instance_id = self.resource_config.remote_instance_id
        for vnic in self.get_vnic_attachments(instance_id):
            self.remove_vnic(vnic_id=vnic.id)

        self.compute_client_ops.terminate_instance_and_wait_for_state(
            instance_id,
            [oci.core.models.Instance.LIFECYCLE_STATE_TERMINATED]
        )

    def remove_vnic(self, vnic_id):
        try:
            self.compute_client_ops.detach_vnic_and_wait_for_state(
                vnic_id,
                [
                    oci.core.models.VnicAttachment.LIFECYCLE_STATE_DETACHED
                ])
        except ServiceError as e:
            if e.status == 409:
                return
        except CompositeOperationError as c_e:
            self._logger.exception("Failed to detach vnic")
            for result in c_e.partial_results:
                if result.data.id == vnic_id \
                        and result.data.lifecycle != oci.core.models.VnicAttachment.LIFECYCLE_STATE_DETACHED:
                    self.compute_client_ops.detach_vnic_and_wait_for_state(
                        vnic_id,
                        [
                            oci.core.models.VnicAttachment.LIFECYCLE_STATE_DETACHED
                        ])

    def create_instance_console(self, instance_id, ssh_pub_key, compartment_ocid, tags):
        create_console = oci.core.models.CreateInstanceConsoleConnectionDetails()
        create_console.freeform_tags = tags
        create_console.instance_id = instance_id
        create_console.public_key = ssh_pub_key
        instance_console_ids = pagination.list_call_get_all_results(
            self.compute_client.list_instance_console_connections,
            compartment_ocid,
            instance_id=instance_id
        )
        result = None
        instance_console_id = next((console_instance for console_instance in instance_console_ids.data), None)
        if instance_console_id:
            result = self.compute_client.get_instance_console_connection(instance_console_id.id)
        if not result:
            result = self.compute_client_ops.create_instance_console_connection_and_wait_for_state(
                create_console,
                wait_for_states=[oci.core.models.InstanceConsoleConnection.LIFECYCLE_STATE_ACTIVE])
        return result

    def create_image_from_instance(self, instance_ocid, compartment_ocid):
        new_image_details = oci.core.models.CreateImageDetails()
        new_image_details.compartment_id = compartment_ocid
        new_image_details.instance_id = instance_ocid

        create_image_response = self.compute_client_ops.create_image_and_wait_for_state(
            new_image_details,
            wait_for_states=[oci.core.models.Image.LIFECYCLE_STATE_AVAILABLE],
            operation_kwargs={"retry_strategy": RETRY_STRATEGY})
        if create_image_response.data:
            return {"OCI Shell.OCI VM from Image.Image ID": create_image_response.data.id}
        else:
            raise RuntimeError("Timeout when waiting for new Image to reach state 'Available'")
