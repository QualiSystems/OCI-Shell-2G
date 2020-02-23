import json

import oci

from cs_oci.helper.shell_helper import OciShellError
from cs_oci.oci_clients.ops.oci_compute_ops import OciComputeOps
from cs_oci.oci_clients.ops.oci_networking_ops import OciNetworkOps
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


class OciOps(object):
    BUCKET_NAME = "CloudshellSSHKeysBucket"

    def __init__(self, resource_config):
        """

        :type resource_config: src.data_model.OCIShellDriverResource
        """
        config = resource_config.oci_config
        self.resource_config = resource_config
        self.storage_client = oci.core.BlockstorageClient(config)
        self.identity_client = oci.identity.IdentityClient(config)
        self.network_ops = OciNetworkOps(resource_config)
        self.compute_ops = OciComputeOps(resource_config)
        self.storage_client_ops = oci.core.BlockstorageClientCompositeOperations(self.storage_client)
        self.object_storage_client = oci.object_storage.ObjectStorageClient(config)
        self.object_storage_client_ops = oci.object_storage.ObjectStorageClientCompositeOperations(
            self.object_storage_client)

    def get_primary_vnic(self, instance_id):
        for vnic_attachment in self.compute_ops.get_vnic_attachments(instance_id):
            vnic = self.network_ops.network_client.get_vnic(vnic_attachment.vnic_id)
            if vnic and vnic.data.is_primary:
                return vnic.data

    def attach_secondary_vnics(self, name, subnet_id, instance_id, is_public, src_dst_check):
        secondary_vnic_details = oci.core.models.CreateVnicDetails(assign_public_ip=is_public,
                                                                   display_name=name,
                                                                   skip_source_dest_check=src_dst_check,
                                                                   subnet_id=subnet_id)
        secondary_vnic_attach_details = oci.core.models.AttachVnicDetails(create_vnic_details=secondary_vnic_details,
                                                                          display_name=name,
                                                                          instance_id=instance_id)
        result = self.compute_ops.compute_client_ops.attach_vnic_and_wait_for_state(
            secondary_vnic_attach_details,
            [
                oci.core.models.VnicAttachment.LIFECYCLE_STATE_ATTACHED
            ])
        vnic_details = self.network_ops.network_client.get_vnic(result.data.vnic_id)

        return json.dumps({
            'interface_id': vnic_details.data.id,
            'IP': vnic_details.data.private_ip,
            'Public IP': vnic_details.data.public_ip,
            'MAC Address': vnic_details.data.mac_address,
        })

    def get_attached_boot_volume(self, instance):
        storage_attachments = self.compute_ops.compute_client.list_boot_volume_attachments(instance.availability_domain,
                                                                                           instance.compartment_id)
        instance_volume = self.storage_client.get_boot_volume(
            next((x.boot_volume_id for x in storage_attachments.data if x.instance_id == instance.id), None))
        return instance_volume.data

    def create_volume_backup(self, instance, snapshot_name, tags):
        boot_volumes = self.compute_ops.compute_client.list_boot_volume_attachments(
            instance.data.availability_domain,
            instance.data.compartment_id,
            instance_id=instance.data.id)
        for instance_volume in boot_volumes.data:
            if instance_volume.instance_id == instance.data.id:
                backup_details = oci.core.models.CreateBootVolumeBackupDetails(
                    boot_volume_id=instance_volume.boot_volume_id,
                    display_name=snapshot_name,
                    freeform_tags=tags,
                    type="FULL"
                )
                self.storage_client_ops.create_boot_volume_backup_and_wait_for_state(
                    backup_details,
                    [oci.core.models.BootVolumeBackup.LIFECYCLE_STATE_AVAILABLE])

    def get_availability_domain_name(self):
        list_availability_domains_response = oci.pagination.list_call_get_all_results(
            self.identity_client.list_availability_domains,
            self.resource_config.compartment_ocid
        )
        return list_availability_domains_response.data[0].name

    def create_ssh_keys_storage(self):
        namespace = self.object_storage_client.get_namespace(
            compartment_id=self.resource_config.compartment_ocid).data
        tags = {"CreatedBy": "Cloudshell"}
        create_bucket_details = oci.object_storage.models.CreateBucketDetails()
        create_bucket_details.name = self.BUCKET_NAME
        create_bucket_details.compartment_id = self.resource_config.compartment_ocid
        create_bucket_details.freeform_tags = tags
        create_bucket_details.public_access_type = "NoPublicAccess"
        return self.object_storage_client.create_bucket(namespace, create_bucket_details)

    def generate_rsa_key_pair(self):
        key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048
        )

        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            crypto_serialization.NoEncryption())
        public_key = key.public_key().public_bytes(crypto_serialization.Encoding.OpenSSH,crypto_serialization.PublicFormat.OpenSSH)
        return private_key, public_key

    def upload_keypairs(self, private_key, public_key):
        namespace = self.object_storage_client.get_namespace(compartment_id=self.resource_config.compartment_ocid).data
        try:
            bucket = self.object_storage_client.get_bucket(namespace, self.BUCKET_NAME).data.name
        except oci.exceptions.ServiceError:
            bucket = self.create_ssh_keys_storage().data.name
        self.object_storage_client.put_object(namespace,
                                              bucket,
                                              self.resource_config.reservation_id,
                                              private_key)
        self.object_storage_client.put_object(namespace,
                                              bucket,
                                              self.resource_config.reservation_id + ".pub",
                                              public_key)

    def get_public_key(self):
        namespace = self.object_storage_client.get_namespace(compartment_id=self.resource_config.compartment_ocid).data
        bucket = self.object_storage_client.get_bucket(namespace, self.BUCKET_NAME).data.name
        return self.object_storage_client.get_object(namespace_name=namespace,
                                                     bucket_name=bucket,
                                                     object_name="{}.pub".format(self.resource_config.reservation_id)
                                                     ).data.content

    def remove_key_pairs(self):
        namespace = self.object_storage_client.get_namespace(compartment_id=self.resource_config.compartment_ocid).data
        bucket = self.object_storage_client.get_bucket(namespace, self.BUCKET_NAME).data.name
        try:
            self.object_storage_client.delete_object(namespace_name=namespace,
                                                     bucket_name=bucket,
                                                     object_name="{}.pub".format(
                                                         self.resource_config.reservation_id))
            self.object_storage_client.delete_object(namespace_name=namespace,
                                                     bucket_name=bucket,
                                                     object_name=self.resource_config.reservation_id)
        except oci.exceptions.ServiceError:
            pass

    def set_as_routing_gw(self, instance_id=None):
        if not instance_id:
            instance_id = self.resource_config.remote_instance_id
            if not instance_id:
                raise OciShellError("Failed to retrieve instance ocid")

        vnic_attachments = self.compute_ops.get_vnic_attachments(instance_id)
        if len(vnic_attachments) < 2:
            raise OciShellError("Unable to setas routing gateway: Only 1 vnic attached")
        for vnic_attachment in vnic_attachments:
            vnic = self.network_ops.network_client.get_vnic(vnic_attachment.vnic_id)
            subnet = self.network_ops.get_subnet(vnic.data.subnet_id)
            vcn_id = subnet.freeform_tags.get("VCN_ID")
            vcn = self.network_ops.network_client.get_vcn(vcn_id)
            route_table = vcn.data.default_route_table
            route_rule = oci.core.models.RouteRule(destination=subnet.cidr_block,
                                                   destination_type="CIDR_BLOCK",
                                                   network_entity_id=vnic.data.private_ip)

            self.network_ops.update_route_table(route_table_id=route_table, route_rule=route_rule)
