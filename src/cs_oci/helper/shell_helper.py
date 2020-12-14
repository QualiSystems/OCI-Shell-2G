import json
import re

import jsonpickle
from cloudshell.cp.core.models import (
    VmDetailsData,
    VmDetailsNetworkInterface,
    VmDetailsProperty,
)
from oci.retry import RetryStrategyBuilder

RETRY_STRATEGY = (
    RetryStrategyBuilder()
    .add_max_attempts(10)
    .add_total_elapsed_time(600)
    .add_service_error_check(
        service_error_retry_on_any_5xx=True,
        service_error_retry_config={
            400: ["QuotaExceeded", "LimitExceeded"],
            409: ["Conflict"],
            429: [],
        },
    )
    .get_retry_strategy()
)


class OciShellError(Exception):
    pass


WIN_SSH_LINK_TEMPLATE = (
    "Start-Job {{ Echo N | plink.exe -i $env:homedrive$env:homepath\\oci\\console.ppk "
    "-N -ssh -P 443 -l {console_conn_id} -L {port1}:{instance_id}:{port2} "
    "{console_conn_endpoint} "
    "}}; sleep 5; plink.exe -i $env:homedrive$env:homepath\\oci\\console.ppk "
    "-P {port1} localhost -l {instance_id}"
)

WIN_VNC_LINK_TEMPLATE = (
    "Start-Job {{ Echo N | plink.exe -i $env:homedrive$env:homepath\\oci\\console.ppk "
    "-N -ssh -P 443 -l {console_conn_id} -L {port1}:{instance_id}:{port1} "
    "{console_conn_endpoint} "
    "}}; sleep 5; plink.exe -i $env:homedrive$env:homepath\\oci\\console.ppk "
    "-N -L {port2}:localhost:{port2} -P {port1} localhost -l {instance_id}"
)


def create_win_console_link(
    instance_id, console_id, region, linux_ssh_link="", linux_vnc_link=""
):
    data_dict = {
        "console_conn_id": console_id,
        "console_conn_endpoint": "instance-console.{}.oraclecloud.com".format(region),
        "port1": 5905,
        "port2": 5900,
        "instance_id": instance_id,
    }
    pattern = r"^.*{}@(?P<console_conn_endpoint>\S+)'".format(console_id)
    endpoint_string_match = re.search(pattern, linux_vnc_link, re.IGNORECASE)
    if endpoint_string_match:
        data_dict.update(endpoint_string_match.groupdict())
    if linux_vnc_link:
        return WIN_VNC_LINK_TEMPLATE.format(**data_dict)
    else:
        # Todo add regexp to read ssh link ports
        data_dict["port1"] = 22000
        data_dict["port2"] = 22
        return WIN_SSH_LINK_TEMPLATE.format(**data_dict)


def get_interface_details_json(vnic_details):
    return json.dumps(
        {
            "interface_id": vnic_details.id,
            "IP": vnic_details.private_ip,
            "Public IP": vnic_details.public_ip,
            "MAC Address": vnic_details.mac_address,
        }
    )


def create_vm_details(oci_ops, instance):
    """Create the VM Details results used for both Deployment and Refresh VM Details.

    :type oci_ops: cs_oci.oci_clients.oci_ops.OciOps
    :param instance:
    :return: VmDetailsData
    """
    vm_name = instance.display_name
    instance_volume = oci_ops.get_attached_boot_volume(instance)

    vm_instance_data = [
        VmDetailsProperty("Instance ID", instance.id),
        VmDetailsProperty("Image ID", instance.image_id),
        VmDetailsProperty("VM Shape", instance.shape),
        VmDetailsProperty("Storage Name", instance_volume.id),
        VmDetailsProperty("Storage Size", "{} GB".format(instance_volume.size_in_gbs)),
        VmDetailsProperty("Compartment ID", instance.compartment_id),
        VmDetailsProperty("Avilability Domain", instance.availability_domain),
    ]

    vm_network_data = []
    vnics = oci_ops.get_vnic_attachments(instance.id)
    for vnic in vnics:
        instance_nic = vnic.oci_vnic

        vm_nic = VmDetailsNetworkInterface()
        vm_nic.interfaceId = instance_nic.id
        vm_nic.networkId = instance_nic.subnet_id
        subnet = oci_ops.network_ops.get_subnet(instance_nic.subnet_id)

        vm_nic.isPrimary = False
        vm_nic.isPredefined = False
        # ToDo find a better way to determine if the vnic is primary or not
        if instance_nic.is_primary:
            vm_nic.isPrimary = True
            vm_nic.isPredefined = True
        vm_nic.privateIpAddress = instance_nic.private_ip
        vm_nic.networkData.append(VmDetailsProperty("IP", instance_nic.private_ip))
        vm_nic.networkData.append(
            VmDetailsProperty("Public IP", instance_nic.public_ip)
        )
        vm_nic.networkData.append(
            VmDetailsProperty("MAC Address", instance_nic.mac_address)
        )
        vm_nic.networkData.append(
            VmDetailsProperty("VLAN Name", vnic.oci_vnic_attachment.vlan_tag)
        )
        vm_nic.networkData.append(
            VmDetailsProperty("Skip src/dst check", instance_nic.skip_source_dest_check)
        )
        if subnet:
            vm_nic.networkData.append(
                VmDetailsProperty("VCN ID", subnet.freeform_tags.get("VCN_ID", ""))
            )

        vm_network_data.append(vm_nic)
    return VmDetailsData(vm_instance_data, vm_network_data, vm_name)


def set_command_result(result, unpicklable=False):
    """Serialize output to JSON.

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
