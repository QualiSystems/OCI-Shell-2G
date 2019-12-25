import oci
from oci import pagination


class OciComputeOps(object):
    INSTANCE_START = "START"
    INSTANCE_STOP = "STOP"
    _INSTANCE_STATE_MAP = {INSTANCE_START: oci.core.models.Instance.LIFECYCLE_STATE_RUNNING,
                           INSTANCE_STOP: oci.core.models.Instance.LIFECYCLE_STATE_STOPPED}

    def __init__(self, resource_config):
        """

        :type resource_config: src.data_model.OCIShellDriverResource
        """
        config = resource_config.oci_config
        self.resource_config = resource_config
        self.compute_client = oci.core.ComputeClient(config)
        self.compute_client_ops = oci.core.ComputeClientCompositeOperations(self.compute_client)

    def change_instance_state(self, instance_id, new_state):
        self.compute_client_ops.instance_action_and_wait_for_state(
            instance_id,
            new_state,
            [self._INSTANCE_STATE_MAP.get(new_state)]
        )

    def launch_instance(self, availability_domain,
                        subnet_id,
                        app_name,
                        public_ip,
                        vm_shape,
                        image_id,
                        ssh_pub_key):

        new_inst_details = oci.core.models.LaunchInstanceDetails()
        # Create LaunchInstanceDetails
        new_inst_details.availability_domain = availability_domain
        new_inst_details.compartment_id = self.resource_config.compartment_ocid
        new_inst_details.subnet_id = subnet_id
        new_inst_details.display_name = app_name
        new_inst_details.freeform_tags = self.resource_config.tags
        new_inst_details.create_vnic_details = oci.core.models.CreateVnicDetails(
            assign_public_ip=public_ip,
            display_name=self.resource_config.reservation_id,
            subnet_id=subnet_id)
        new_inst_details.shape = vm_shape
        new_inst_details.image_id = image_id
        new_inst_details.metadata = {'ssh_authorized_keys': ssh_pub_key}

        # Start the VM
        launch_instance_response = self.compute_client_ops.launch_instance_and_wait_for_state(
            new_inst_details,
            wait_for_states=[oci.core.models.Instance.LIFECYCLE_STATE_RUNNING],
            operation_kwargs={"retry_strategy": oci.retry.DEFAULT_RETRY_STRATEGY})
        if launch_instance_response.data:
            return launch_instance_response.data
        else:
            raise RuntimeError("Timeout when waiting for VM to Power on")

    def get_windows_credentials(self, instance_id):
        try:
            instance_credentials = self.compute_client.get_windows_instance_initial_credentials(instance_id)
            user = instance_credentials.data.username
            password = instance_credentials.data.password
            return user, password
        except (oci.exceptions.ServiceError, oci.exceptions.RequestException):
            pass

    def get_vnic_attachments(self, instance_id):
        vnic_attachments = self.compute_client.list_vnic_attachments(self.resource_config.compartment_ocid)
        return [vnic for vnic in vnic_attachments.data if vnic.instance_id == instance_id]

    def update_instance_name(self, name, instance_id):
        instance_update = oci.core.models.UpdateInstanceDetails()
        instance_update.display_name = name

        self.compute_client_ops.update_instance_and_wait_for_state(
            instance_id,
            instance_update,
            wait_for_states=[oci.core.models.Instance.LIFECYCLE_STATE_RUNNING])

    def terminate_instance(self):
        self.compute_client_ops.terminate_instance_and_wait_for_state(
            self.resource_config.remote_instance_id,
            [oci.core.models.Instance.LIFECYCLE_STATE_TERMINATED]
        )

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
