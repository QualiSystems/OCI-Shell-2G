import re

import jsonpickle
from cloudshell.cp.core.models import VmDetailsProperty, VmDetailsNetworkInterface, VmDetailsData


class OciShellError(Exception):
    pass


WIN_SSH_LINK_TEMPLATE = "Start-Job {{ Echo N | plink.exe -i $env:homedrive$env:homepath\oci\console.ppk " \
                       "-N -ssh -P 443 -l {console_conn_id} -L {port1}:{instance_id}:{port2} {console_conn_endpoint} " \
                       "}}; sleep 5; plink.exe -i $env:homedrive$env:homepath\oci\console.ppk " \
                       "-P {port1} localhost -l {instance_id}"

WIN_VNC_LINK_TEMPLATE = "Start-Job {{ Echo N | plink.exe -i $env:homedrive$env:homepath\oci\console.ppk " \
                       "-N -ssh -P 443 -l {console_conn_id} -L {port1}:{instance_id}:{port1} {console_conn_endpoint} " \
                       "}}; sleep 5; plink.exe -i $env:homedrive$env:homepath\oci\console.ppk " \
                       "-N -L {port2}:localhost:{port2} -P {port1} localhost -l {instance_id}"


def create_win_console_link(instance_id, console_id, region, linux_ssh_link="", linux_vnc_link=""):
    data_dict = {
        "console_conn_id": console_id,
        "console_conn_endpoint": "instance-console.{}.oraclecloud.com".format(region),
        "port1": 5905,
        "port2": 5900,
        "instance_id": instance_id
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


def create_vm_details(resource_config, oci_ops, vm_name, deployment_service_name, instance):
    """ Create the VM Details results used for both Deployment and Refresh VM Details
    :param resource_config:
    :type oci_ops: OciOps
    :param vm_name:
    :param deployment_service_name:
    :param instance:
    :return: VmDetailsData
    """

    instance_volume = oci_ops.get_attached_boot_volume(instance)

    vm_instance_data = [
        VmDetailsProperty("Instance ID", instance.id),
        VmDetailsProperty("Image ID", instance.image_id),
        VmDetailsProperty("VM Shape", instance.shape),
        VmDetailsProperty("Storage Name", instance_volume.id),
        VmDetailsProperty("Storage Size", "{} GB".format(instance_volume.size_in_gbs)),
        VmDetailsProperty("Compartment ID", instance.compartment_id),
        VmDetailsProperty("Avilability Domain", instance.availability_domain)
    ]

    vm_network_data = []
    vnic_attachments = oci_ops.compute_ops.get_vnic_attachments(instance.id)
    for vnic in vnic_attachments:
        instance_nic = oci_ops.network_ops.network_client.get_vnic(vnic.vnic_id)

        vm_nic = VmDetailsNetworkInterface()
        vm_nic.interfaceId = instance_nic.data.id
        vm_nic.networkId = instance_nic.data.subnet_id
        vm_nic.isPrimary = False
        vm_nic.isPredefined = False
        # ToDo find a better way to determine if the vnic is primary or not
        if vnic.display_name == resource_config.reservation_id or vnic.display_name is None:
            vm_nic.isPrimary = True
            vm_nic.isPredefined = True
        vm_nic.privateIpAddress = instance_nic.data.private_ip
        vm_nic.networkData.append(VmDetailsProperty("IP", instance_nic.data.private_ip))
        vm_nic.networkData.append(VmDetailsProperty("Public IP", instance_nic.data.public_ip))
        vm_nic.networkData.append(VmDetailsProperty("MAC Address", instance_nic.data.mac_address))
        vm_nic.networkData.append(VmDetailsProperty("VLAN Name", vnic.vlan_tag))
        vm_nic.networkData.append(VmDetailsProperty("Skip src/dst check", instance_nic.data.skip_source_dest_check))
        vm_network_data.append(vm_nic)
    return VmDetailsData(vm_instance_data, vm_network_data, vm_name)


def set_command_result(result, unpicklable=False):
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
