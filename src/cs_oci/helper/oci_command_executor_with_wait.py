import oci

from cs_oci.helper.shell_helper import OciShellError


def call_oci_command_with_waiter(network_client, cmd_to_call,
                     cmd_to_check_status,
                     ocid_to_check=None,
                     state_to_check="lifecycle_state",
                     wait_for_states=None,
                     cmd_kwargs=None,
                     waiter_kwargs=None):
    if not wait_for_states:
        wait_for_states = []
    if not cmd_kwargs:
        cmd_kwargs = {}
    if not waiter_kwargs:
        waiter_kwargs = {}

    if ocid_to_check:
        wait_for_resource_id = ocid_to_check
        current_object = cmd_to_check_status(wait_for_resource_id)
        if current_object.data and hasattr(current_object.data, state_to_check):
            current_state = getattr(current_object.data, state_to_check)
            if current_state in wait_for_states:
                return current_object.data

    operation_result = cmd_to_call(**cmd_kwargs)

    if not wait_for_states:
        return operation_result
    if operation_result.data:
        wait_for_resource_id = operation_result.data.id
    if not wait_for_resource_id:
        raise OciShellError("Unable to check for state: OCID not found")

    lowered_wait_for_states = [w.lower() for w in wait_for_states]

    try:
        waiter_result = oci.wait_until(
            network_client,
            cmd_to_check_status(wait_for_resource_id),
            evaluate_response=lambda r: getattr(r.data, state_to_check
                                                ) and getattr(r.data, state_to_check
                                                              ).lower() in lowered_wait_for_states,
            **waiter_kwargs
        )
        result_to_return = waiter_result

        return result_to_return
    except Exception as e:
        raise oci.exceptions.CompositeOperationError(partial_results=[operation_result], cause=e)
