

class InstanceDetails(object):
    def __init__(self, deploy_attribs):
        self._deploy_attribs = deploy_attribs

    @property
    def image_id(self):
        return self._get_val_by_key_suffix("Image ID")

    @property
    def public_ip(self):
        public_ip_str = self._get_val_by_key_suffix("Public IP")
        return public_ip_str.lower() == "true"

    @property
    def vm_shape(self):
        return self._get_val_by_key_suffix("VM Shape")

    @property
    def inbound_ports(self):
        return self._get_val_by_key_suffix("Inbound Ports")

    @property
    def user(self):
        return self._get_val_by_key_suffix("User")

    @property
    def password(self):
        return self._get_val_by_key_suffix("Password")

    def _get_val_by_key_suffix(self, suffix):
        """ Helper function - get the attribute value for an attribute in a dictionary by its Suffix
        :param suffix: the suffix to look for
        :return:
        """

        return next((val for att, val in self._deploy_attribs.items() if att.endswith(suffix)), "")
