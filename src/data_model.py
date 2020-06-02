from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.session.logging_session import LoggingSessionContext

from cs_oci.helper.quali_api_helper import QualiAPIHelper


class OCIShellDriverResource(object):
    def __init__(self, name, context):
        """
        
        """
        self.attributes = {}
        self.resources = {}
        self._context = context
        self._cs_model_name = 'OCI Shell 2G'
        self._name = name

    @classmethod
    def create_from_context(cls, context):
        """
        Creates an instance of NXOS by given context
        :param context: Command context
        :type context: ResourceCommandContext, ResourceRemoteCommandContext
        :return:
        :rtype: OCIShellDriverResource
        """
        result = OCIShellDriverResource(name=context.resource.name, context=context)
        for attr in context.resource.attributes:
            result.attributes[attr] = context.resource.attributes[attr]
        return result

    @property
    def api(self):
        """

        :return: CloudShell API Session Object
        :rtype: cloudshell.api.cloudshell_api.CloudShellAPISession
        """
        return CloudShellSessionContext(self._context).get_api()

    @property
    def quali_api_helper(self):
        if hasattr(self._context, 'reservation'):
            domain = self._context.reservation.domain
        elif hasattr(self._context, 'remote_reservation') and self._context.remote_reservation:
            domain = self._context.remote_reservation.domain
        else:
            domain = "Global"
        address = self._context.connectivity.server_address
        token = self._context.connectivity.admin_auth_token
        use_https = self._context.connectivity.cloudshell_api_scheme.lower() == "https"
        # instance = QualiAPIHelper(address, username="admin", password="admin", domain=domain, use_https=use_https)
        instance = QualiAPIHelper(address, token=token, domain=domain, use_https=use_https)

        return instance

    @property
    def reservation_id(self):
        if hasattr(self._context, "remote_reservation"):
            reservation = self._context.remote_reservation
        else:
            reservation = self._context.reservation
        return reservation.reservation_id

    @property
    def tags(self):
        if hasattr(self._context, "remote_reservation"):
            reservation = self._context.remote_reservation
        else:
            reservation = self._context.reservation
        return {
            "CreatedBy": "Cloudshell",
            "ReservationId": reservation.reservation_id,
            "Owner": reservation.owner_user,
            "Domain": reservation.domain,
            "Blueprint": reservation.environment_name
        }

    def get_logger(self):
        return LoggingSessionContext(self._context)

    @property
    def oci_config(self):
        return {
            "user": self.api_user_id,
            "key_file": self.api_key_file_path,
            "pass_phrase": self.api_key_passphrase,
            "fingerprint": self.api_key_file_fingerprint,
            "tenancy": self.tenant_id,
            "region": self.region
        }

    @property
    def remote_instance_id(self):
        """ Retrieve UID of the VM the resource represents
        :return:
        """

        endpoint = self._context.remote_endpoints[0].fullname.split('/')[0]
        parent_connected_resource = self.api.GetResourceDetails(endpoint)
        instance_id = parent_connected_resource.VmDetails.UID
        return instance_id

    @property
    def api_user_id(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.API User ID'.format(self._cs_model_name))

    @property
    def api_key_file_path(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.API Key File Path'.format(self._cs_model_name))

    @property
    def api_key_passphrase(self):
        """
        :rtype: str
        """

        password = self.attributes.get('{}.API Key Passphrase'.format(self._cs_model_name))
        if password:
            password = self.api.DecryptPassword(password).Value
        return password

    @property
    def api_key_file_fingerprint(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.API Key File Fingerprint'.format(self._cs_model_name))

    @property
    def tenant_id(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.Tenant ID'.format(self._cs_model_name))

    @property
    def default_subnet(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.Default Subnet'.format(self._cs_model_name))

    @property
    def availability_domain(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.Availability Domain'.format(self._cs_model_name))

    @property
    def compartment_ocid(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.Compartment OCID'.format(self._cs_model_name))

    @property
    def region(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.Region'.format(self._cs_model_name))

    @property
    def networking_type(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.Networking type'.format(self._cs_model_name))

    @property
    def networks_in_use(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.Networks in use'.format(self._cs_model_name))

    @property
    def vlan_type(self):
        """
        :rtype: str
        """
        return self.attributes.get('{}.VLAN Type'.format(self._cs_model_name))

    @property
    def name(self):
        """
        :rtype: str
        """
        return self._name

    @property
    def cloudshell_model_name(self):
        """
        :rtype: str
        """
        return self._cs_model_name
