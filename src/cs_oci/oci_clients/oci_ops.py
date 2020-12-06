import json
import re
import time

import oci
from oci.exceptions import CompositeOperationError, ServiceError

from cs_oci.helper.shell_helper import OciShellError, RETRY_STRATEGY
from cs_oci.model.vnic import VNIC
from cs_oci.oci_clients.ops.oci_compute_ops import OciComputeOps
from cs_oci.oci_clients.ops.oci_networking_ops import OciNetworkOps
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


class OciOps(object):
    BUCKET_NAME = "CloudshellSSHKeysBucket"
    VNIC_PATTERN = re.compile(r"ocid1.vnic\S+", re.IGNORECASE)

    def __init__(self, resource_config, logger):
        """

        :type resource_config: src.data_model.OCIShellDriverResource
        """
        config = resource_config.oci_config
        self._logger = logger
        self.resource_config = resource_config
        self.storage_client = oci.core.BlockstorageClient(config, retry_strategy=RETRY_STRATEGY)
        self.identity_client = oci.identity.IdentityClient(config, retry_strategy=RETRY_STRATEGY)
        self.network_ops = OciNetworkOps(resource_config=resource_config, logger=logger)
        self.compute_ops = OciComputeOps(resource_config=resource_config, logger=logger)
        self.storage_client_ops = oci.core.BlockstorageClientCompositeOperations(self.storage_client)
        self.object_storage_client = oci.object_storage.ObjectStorageClient(config)
        self.object_storage_client_ops = oci.object_storage.ObjectStorageClientCompositeOperations(
            self.object_storage_client)

    def get_vnic_attachments(self, instance_id):
        i = 0
        vnic_attachments = None
        while not vnic_attachments and i != self.compute_ops.VNIC_ATTACHMENT_RETRY:
            time.sleep(self.compute_ops.VNIC_ATTACHMENT_TIMEOUT)
            oci_vnic_attachments = self.compute_ops.get_vnic_attachments(instance_id)
            vnic_attachments = [VNIC(oci_ops=self, logger=self._logger, vnic_attachment=vnic_att)
                                for vnic_att in oci_vnic_attachments
                                if vnic_att]
            i += 1

        return vnic_attachments

    def get_primary_vnic(self, instance_id, retries=6, timeout=5):
        result = None
        i = 0
        while not result and i != retries:
            time.sleep(timeout)
            attachments = self.get_vnic_attachments(instance_id)
            for attachment in attachments:
                self._logger.info("Found {} vnic attachments".format(len(attachments)))

                self._logger.info("Attached vnic is {} is primary {}".format(
                    attachment.oci_vnic.display_name,
                    attachment.oci_vnic.is_primary))
            result = next((x for x in attachments if x.oci_vnic.is_primary), None)
            i += 1

        return result

    def _attach_secondary_vnic(self, name, subnet_id, instance_id, is_public, private_ip, src_dst_check,
                               retries=3, timeout=5):
        attachments = self.get_vnic_attachments(instance_id)
        attached_vnic = next((x for x in attachments
                              if x.oci_vnic_attachment.display_name == name
                              and x.oci_vnic_attachment.subnet_id == subnet_id), None)
        if attached_vnic:
            return attached_vnic
        secondary_vnic_details = oci.core.models.CreateVnicDetails(assign_public_ip=is_public,
                                                                   display_name=name,
                                                                   skip_source_dest_check=src_dst_check,
                                                                   subnet_id=subnet_id)
        if private_ip:
            if private_ip.name:
                secondary_vnic_details.display_name = private_ip.name
            if private_ip.ip:
                secondary_vnic_details.private_ip = private_ip.ip
        secondary_vnic_attach_details = oci.core.models.AttachVnicDetails(create_vnic_details=secondary_vnic_details,
                                                                          display_name=name,
                                                                          instance_id=instance_id)
        result = None
        try:
            result = self.compute_ops.compute_client_ops.attach_vnic_and_wait_for_state(
                secondary_vnic_attach_details,
                [
                    oci.core.models.VnicAttachment.LIFECYCLE_STATE_ATTACHED
                ])
        except CompositeOperationError as e:
            for partial_result in e.partial_results:
                if partial_result and partial_result.data:
                    if partial_result.data.lifecycle == oci.core.models.VnicAttachment.LIFECYCLE_STATE_ATTACHED:
                        result = partial_result
                        break
                    if partial_result.data.lifecycle == oci.core.models.VnicAttachment.LIFECYCLE_STATE_ATTACHING:
                        vnic = self.compute_ops.compute_client.get_vnic_attachment(partial_result.data.id)
                        i = 0
                        while vnic.data.lifecycle != oci.core.models.VnicAttachment.LIFECYCLE_STATE_ATTACHED\
                                and i < retries:
                            time.sleep(timeout)
                            vnic = self.compute_ops.compute_client.get_vnic_attachment(partial_result.data.id)
                            i += 1
                        result = vnic
                        if vnic.data.lifecycle != oci.core.models.VnicAttachment.LIFECYCLE_STATE_ATTACHED:
                            raise OciShellError("Failed to attach vnic {} to instance {}".format(
                                name,
                                instance_id
                            ))
        if result:
            vnic = VNIC(oci_ops=self, logger=self._logger, vnic_attachment=result.data)
            attachments = self.get_vnic_attachments(instance_id)
            if any(vnic for vnic in attachments if vnic.oci_vnic_attachment.id == vnic.oci_vnic_attachment.id):
                return vnic.oci_vnic

    def attach_secondary_vnic(self, name, subnet_id, instance_id, is_public, private_ip, src_dst_check, retry_count=3,
                              retry_timeout=2):
        result = self._attach_secondary_vnic(name, subnet_id, instance_id, is_public, private_ip, src_dst_check)
        i = 0
        while not result and i < retry_count:
            time.sleep(retry_timeout)
            result = self._attach_secondary_vnic(name, subnet_id, instance_id, is_public, private_ip, src_dst_check)
        return result

    def get_attached_boot_volume(self, instance):
        storage_attachments = oci.pagination.list_call_get_all_results(
            self.compute_ops.compute_client.list_boot_volume_attachments,
            availability_domain=instance.availability_domain,
            compartment_id=instance.compartment_id,
            instance_id=instance.id).data
        instance_volume = self.storage_client.get_boot_volume(
            next((x.boot_volume_id for x in storage_attachments if x.instance_id == instance.id), None))
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
        if self.resource_config.availability_domain:
            if any(x for x in list_availability_domains_response.data
                   if x.name == self.resource_config.availability_domain):
                return self.resource_config.availability_domain
            try:
                index = int(self.resource_config.availability_domain) - 1
                return list_availability_domains_response.data[index].name
            except (ValueError, IndexError) as e:
                pass
                # Todo add logging here
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
        public_key = key.public_key().public_bytes(crypto_serialization.Encoding.OpenSSH,
                                                   crypto_serialization.PublicFormat.OpenSSH)
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

        routes_to_create = {}
        for vnic_attachment in vnic_attachments:
            vnic = self.network_ops.network_client.get_vnic(vnic_attachment.vnic_id)
            subnet = self.network_ops.get_subnet(vnic.data.subnet_id)

            ip_id = self.network_ops.get_private_ip_object(subnet.id, vnic.data.private_ip)
            route_rule = oci.core.models.RouteRule(destination_type="CIDR_BLOCK",
                                                   network_entity_id=ip_id.id)

            if not vnic.data.skip_source_dest_check:
                self.network_ops.network_client_ops.update_vnic_and_wait_for_state(
                    vnic.data.id,
                    oci.core.models.UpdateVnicDetails(skip_source_dest_check=True),
                    wait_for_states=[oci.core.models.Vnic.LIFECYCLE_STATE_AVAILABLE])
            routes_to_create[subnet] = route_rule

        for subnet in routes_to_create:
            rule = routes_to_create.get(subnet)
            route_table = subnet.route_table_id
            for dst_subnet in routes_to_create:
                if subnet == dst_subnet:
                    continue
                rule.destination = dst_subnet.cidr_block
                self.network_ops.update_route_table(route_table_id=route_table, route_rule=rule)

    def remove_vcn(self, subnet_retires=6):
        vcns = self.network_ops.get_vcn_by_tag(self.resource_config.reservation_id)
        error_list = []
        for vcn in vcns:
            subnets = self.network_ops.get_subnets(vcn_id=vcn.id) or []
            service_gateways = self.network_ops.get_service_gateways(vcn_id=vcn.id) or []
            internet_gateways = self.network_ops.get_inet_gateways(vcn_id=vcn.id) or []
            lpgs = self.network_ops.get_local_peering_gws(vcn_id=vcn.id)
            for subnet in subnets:
                i = 0
                while i < subnet_retires:
                    try:
                        self.network_ops.remove_subnet(subnet)
                        break
                    except ServiceError as e:
                        self._logger.exception("Unable to remove subnet {}".format(subnet.display_name))
                        vnic_id_match = self.VNIC_PATTERN.search(e.message)
                        if vnic_id_match:
                            vnic_id = vnic_id_match.group().rstrip('.,')
                            self.compute_ops.remove_vnic(vnic_id)
                    except Exception:
                        self._logger.exception("Unable to remove subnet {}".format(subnet.display_name))
                        error_list.append(subnet.display_name)
                        break
                else:
                    error_list.append(subnet.display_name)
            for route_table in self.network_ops.get_routing_tables(vcn.id):
                if route_table.id != vcn.default_route_table_id:
                    self.network_ops.network_client_ops.delete_route_table_and_wait_for_state(
                        route_table.id,
                        [oci.core.models.RouteTable.LIFECYCLE_STATE_TERMINATED]
                    )
            for local_peering_gw in lpgs:
                self.network_ops.network_client_ops.delete_local_peering_gateway_and_wait_for_state(
                    local_peering_gw.id,
                    wait_for_states=[oci.core.models.LocalPeeringGateway.LIFECYCLE_STATE_TERMINATED]
                )
            for service_gw in service_gateways:
                self.network_ops.network_client_ops.delete_service_gateway_and_wait_for_state(
                    service_gw.id,
                    [oci.core.models.ServiceGateway.LIFECYCLE_STATE_TERMINATED]
                )
            security_lists = self.network_ops.network_client.list_security_lists(self.resource_config.compartment_ocid,
                                                                     vcn_id=vcn.id)
            for security_list in security_lists.data:
                if vcn.default_security_list_id == security_list.id:
                    continue
                self.network_ops.network_client_ops.delete_security_list_and_wait_for_state(
                    security_list.id,
                    [oci.core.models.SecurityList.LIFECYCLE_STATE_TERMINATED])
            for internet_gw in internet_gateways:
                self.network_ops.network_client_ops.delete_internet_gateway_and_wait_for_state(
                    internet_gw.id,
                    wait_for_states=[oci.core.models.InternetGateway.LIFECYCLE_STATE_TERMINATED]
                )
            try:
                self.network_ops.network_client_ops.delete_vcn_and_wait_for_state(
                    vcn.id,
                    [oci.core.models.Vcn.LIFECYCLE_STATE_TERMINATED])
            except ServiceError as vcn_e:
                self._logger.exception("Failed to delete VCN {}".format(vcn.display_name))
                error_list.append(vcn.display_name)

            if error_list:
                self._logger.error("The following items were not removed {}".format(error_list))
                raise OciShellError("Unable to cleanup sandbox. Please see logs for details.")
