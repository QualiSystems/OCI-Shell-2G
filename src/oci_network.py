import oci


def get_availability_domain(identity_client, compartment_id):
    list_availability_domains_response = oci.pagination.list_call_get_all_results(
        identity_client.list_availability_domains,
        compartment_id
    )
    # For demonstration, we just return the first availability domain but for Production code you should
    # have a better way of determining what is needed
    availability_domain = list_availability_domains_response.data[0]

    print()
    print('Running in Availability Domain: {}'.format(availability_domain.name))

    return availability_domain

def create_vcn_and_subnets(virtual_network_client_composite_ops, cidr, compartment_id, first_ad, second_ad):
    # Here we use a composite operation to create a VCN and wait for it to enter the given state. Note that the
    # states are passed as an array so it is possible to wait on multiple states. The waiter will complete
    # (and the method will return) once the resource enters ANY of the provided states.
    get_vcn_response = virtual_network_client_composite_ops.create_vcn_and_wait_for_state(
        oci.core.models.CreateVcnDetails(
            cidr_block=cidr,
            display_name='PySdkCompositeOpExample',
            compartment_id=compartment_id
        ),
        [oci.core.models.Vcn.LIFECYCLE_STATE_AVAILABLE]
    )
    vcn = get_vcn_response.data
    print('Created VCN')

    get_subnet_response = virtual_network_client_composite_ops.create_subnet_and_wait_for_state(
        oci.core.models.CreateSubnetDetails(
            compartment_id=compartment_id,
            availability_domain=first_ad,
            display_name='PySdkCompositeOpsExampleSubnet1',
            vcn_id=vcn.id,
            cidr_block='10.0.0.0/24'
        ),
        [oci.core.models.Subnet.LIFECYCLE_STATE_AVAILABLE]
    )
    subnet_one = get_subnet_response.data
    print('Created Subnet 1')

    get_subnet_response = virtual_network_client_composite_ops.create_subnet_and_wait_for_state(
        oci.core.models.CreateSubnetDetails(
            compartment_id=compartment_id,
            availability_domain=second_ad,
            display_name='PySdkCompositeOpsExampleSubnet2',
            vcn_id=vcn.id,
            cidr_block='10.0.1.0/24'
        ),
        [oci.core.models.Subnet.LIFECYCLE_STATE_AVAILABLE]
    )
    subnet_two = get_subnet_response.data
    print('Created Subnet 2')