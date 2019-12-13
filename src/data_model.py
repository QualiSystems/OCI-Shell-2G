from cloudshell.shell.core.driver_context import ResourceCommandContext, AutoLoadDetails, AutoLoadAttribute, \
    AutoLoadResource
from collections import defaultdict


class OCIShellDriverResource(object):
    def __init__(self, name):
        """
        
        """
        self.attributes = {}
        self.resources = {}
        self._cloudshell_model_name = 'OCI Shell'
        self._name = name

    def add_sub_resource(self, relative_path, sub_resource):
        self.resources[relative_path] = sub_resource

    @classmethod
    def create_from_context(cls, context):
        """
        Creates an instance of NXOS by given context
        :param context: cloudshell.shell.core.driver_context.ResourceCommandContext
        :type context: cloudshell.shell.core.driver_context.ResourceCommandContext
        :return:
        :rtype OCIShellDriverResource
        """
        result = OCIShellDriverResource(name=context.resource.name)
        for attr in context.resource.attributes:
            result.attributes[attr] = context.resource.attributes[attr]
        return result

    def create_autoload_details(self, relative_path=''):
        """
        :param relative_path:
        :type relative_path: str
        :return
        """
        resources = [AutoLoadResource(model=self.resources[r].cloudshell_model_name,
                                      name=self.resources[r].name,
                                      relative_address=self._get_relative_path(r, relative_path))
                     for r in self.resources]
        attributes = [AutoLoadAttribute(relative_path, a, self.attributes[a]) for a in self.attributes]
        autoload_details = AutoLoadDetails(resources, attributes)
        for r in self.resources:
            curr_path = relative_path + '/' + r if relative_path else r
            curr_auto_load_details = self.resources[r].create_autoload_details(curr_path)
            autoload_details = self._merge_autoload_details(autoload_details, curr_auto_load_details)
        return autoload_details

    def _get_relative_path(self, child_path, parent_path):
        """
        Combines relative path
        :param child_path: Path of a model within it parent model, i.e 1
        :type child_path: str
        :param parent_path: Full path of parent model, i.e 1/1. Might be empty for root model
        :type parent_path: str
        :return: Combined path
        :rtype str
        """
        return parent_path + '/' + child_path if parent_path else child_path

    @staticmethod
    def _merge_autoload_details(autoload_details1, autoload_details2):
        """
        Merges two instances of AutoLoadDetails into the first one
        :param autoload_details1:
        :type autoload_details1: AutoLoadDetails
        :param autoload_details2:
        :type autoload_details2: AutoLoadDetails
        :return:
        :rtype AutoLoadDetails
        """
        for attribute in autoload_details2.attributes:
            autoload_details1.attributes.append(attribute)
        for resource in autoload_details2.resources:
            autoload_details1.resources.append(resource)
        return autoload_details1

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
            'OCI Shell.Default Availability Domain'] if 'OCI Shell.Default Availability Domain' in self.attributes else None

    @default_availability_domain.setter
    def default_availability_domain(self, value):
        """
        Full name of the Default Availability Domain for VM deployments (example "rJhM\:EU-FRANKFURT-1-AD-1")
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
        Reserved network ranges to be excluded when allocated sandbox networks (for cloud providers with L3 networking). The syntax is a comma separated CIDR list. For example "10.0.0.0/24, 10.1.0.0/26"
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
