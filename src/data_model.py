from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.session.logging_session import LoggingSessionContext

from quali_api_helper import QualiAPIHelper


class OCIShellDriverResource(object):
    def __init__(self, name, context):
        """
        
        """
        self.attributes = {}
        self.resources = {}
        self._context = context
        self._cloudshell_model_name = 'OCI Shell'
        self._name = name

    @classmethod
    def create_from_context(cls, context):
        """
        Creates an instance of NXOS by given context
        :param context: Command context
        :type context: ResourceCommandContext, ResourceRemoteCommandContext
        :return:
        :rtype OCIShellDriverResource
        """
        result = OCIShellDriverResource(name=context.resource.name, context=context)
        for attr in context.resource.attributes:
            result.attributes[attr] = context.resource.attributes[attr]
        return result

    @property
    def api(self):
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
        instance = QualiAPIHelper(address, token=token, domain=domain, use_https=use_https)
        # if token:
        #     instance = QualiAPIHelper(address, token=token, domain=domain, use_https=use_https)
        # else:
        #     instance = QualiAPIHelper(address, username='admin', password='admin', domain=domain)
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
        try:
            instance_id = [attribute.Value for attribute in parent_connected_resource.ResourceAttributes if
                           attribute.Name == 'VM_UUID'][0]
        except Exception:
            instance_id = parent_connected_resource.VmDetails.UID
        return instance_id

    @property
    def api_user_id(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.API User ID'] if 'OCI Shell.API User ID' in self.attributes else None

    @api_user_id.setter
    def api_user_id(self, value):
        """
        User ID for OCI API
        :type value: str
        """
        self.attributes['OCI Shell.API User ID'] = value

    @property
    def api_key_file_path(self):
        """
        :rtype: str
        """
        return self.attributes[
            'OCI Shell.API Key File Path'] if 'OCI Shell.API Key File Path' in self.attributes else None

    @api_key_file_path.setter
    def api_key_file_path(self, value):
        """
        Full path (including file name) to the API Private Key
        :type value: str
        """
        self.attributes['OCI Shell.API Key File Path'] = value

    @property
    def api_key_passphrase(self):
        """
        :rtype: str
        """
        return self.attributes[
            'OCI Shell.API Key Passphrase'] if 'OCI Shell.API Key Passphrase' in self.attributes else None

    @api_key_passphrase.setter
    def api_key_passphrase(self, value):
        """
        API Private Key passphrase
        :type value: str
        """
        self.attributes['OCI Shell.API Key Passphrase'] = value

    @property
    def api_key_file_fingerprint(self):
        """
        :rtype: str
        """
        return self.attributes[
            'OCI Shell.API Key File Fingerprint'] if 'OCI Shell.API Key File Fingerprint' in self.attributes else None

    @api_key_file_fingerprint.setter
    def api_key_file_fingerprint(self, value):
        """
        Fingerprint for the API Public key
        :type value: str
        """
        self.attributes['OCI Shell.API Key File Fingerprint'] = value

    @property
    def tenant_id(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.Tenant ID'] if 'OCI Shell.Tenant ID' in self.attributes else None

    @tenant_id.setter
    def tenant_id(self, value):
        """
        OCID of the OCI Tenant to deploy on
        :type value: str
        """
        self.attributes['OCI Shell.Tenant ID'] = value

    @property
    def default_subnet(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.Default Subnet'] if 'OCI Shell.Default Subnet' in self.attributes else None

    @default_subnet.setter
    def default_subnet(self, value):
        """
        OCID of the Default Subnet for VM deployments
        :type value: str
        """
        self.attributes['OCI Shell.Default Subnet'] = value

    @property
    def default_availability_domain(self):
        """
        :rtype: str
        """
        return self.attributes[
            'OCI Shell.Default Availability Domain'] \
            if 'OCI Shell.Default Availability Domain' in self.attributes else None

    @default_availability_domain.setter
    def default_availability_domain(self, value):
        """
        Full name of the Default Availability Domain for VM deployments (example "rJhM:EU-FRANKFURT-1-AD-1")
        :type value: str
        """
        self.attributes['OCI Shell.Default Availability Domain'] = value

    @property
    def compartment_ocid(self):
        """
        :rtype: str
        """
        return self.attributes[
            'OCI Shell.Compartment OCID'] if 'OCI Shell.Compartment OCID' in self.attributes else None

    @compartment_ocid.setter
    def compartment_ocid(self, value):
        """
        OCID of the Default Compartment for VM deployments
        :type value: str
        """
        self.attributes['OCI Shell.Compartment OCID'] = value

    @property
    def region(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.Region'] if 'OCI Shell.Region' in self.attributes else None

    @region.setter
    def region(self, value=''):
        """
        OCI Region of the Cloud Provider
        :type value: str
        """
        self.attributes['OCI Shell.Region'] = value

    @property
    def default_keypair(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.Default Keypair'] if 'OCI Shell.Default Keypair' in self.attributes else None

    @default_keypair.setter
    def default_keypair(self, value):
        """
        Name of default Keypair for new instances
        :type value: str
        """
        self.attributes['OCI Shell.Default Keypair'] = value

    @property
    def keypairs_path(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.Keypairs Path'] if 'OCI Shell.Keypairs Path' in self.attributes else None

    @keypairs_path.setter
    def keypairs_path(self, value):
        """
        Path to Local Keypair repository
        :type value: str
        """
        self.attributes['OCI Shell.Keypairs Path'] = value

    @property
    def networking_type(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.Networking type'] if 'OCI Shell.Networking type' in self.attributes else None

    @networking_type.setter
    def networking_type(self, value):
        """
        networking type that the cloud provider implements- L2 networking (VLANs) or L3 (Subnets)
        :type value: str
        """
        self.attributes['OCI Shell.Networking type'] = value

    @property
    def networks_in_use(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.Networks in use'] if 'OCI Shell.Networks in use' in self.attributes else None

    @networks_in_use.setter
    def networks_in_use(self, value=''):
        """
        Reserved network ranges to be excluded when allocated sandbox networks (for cloud providers with L3 networking).
        The syntax is a comma separated CIDR list. For example "10.0.0.0/24, 10.1.0.0/26"
        :type value: str
        """
        self.attributes['OCI Shell.Networks in use'] = value

    @property
    def vlan_type(self):
        """
        :rtype: str
        """
        return self.attributes['OCI Shell.VLAN Type'] if 'OCI Shell.VLAN Type' in self.attributes else None

    @vlan_type.setter
    def vlan_type(self, value='VLAN'):
        """
        whether to use VLAN or VXLAN (for cloud providers with L2 networking)
        :type value: str
        """
        self.attributes['OCI Shell.VLAN Type'] = value

    @property
    def name(self):
        """
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, value):
        """
        
        :type value: str
        """
        self._name = value

    @property
    def cloudshell_model_name(self):
        """
        :rtype: str
        """
        return self._cloudshell_model_name

    @cloudshell_model_name.setter
    def cloudshell_model_name(self, value):
        """
        
        :type value: str
        """
        self._cloudshell_model_name = value
