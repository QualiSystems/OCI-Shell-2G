

class VNIC:
    def __init__(self, oci_ops, logger, vnic_attachment):
        self._oci_ops = oci_ops
        self._logger = logger
        self._vnic_attachment = vnic_attachment
        self._oci_vnic = None

    @property
    def oci_vnic_attachment(self):
        """

        :rtype: oci.core.models.VnicAttachment
        """
        if self._vnic_attachment:
            return self._vnic_attachment

    @property
    def oci_vnic(self):
        """

        :rtype: oci.core.models.vnic.Vnic
        """
        if not self._oci_vnic and self._vnic_attachment:
            self._oci_vnic = self._oci_ops.network_ops.network_client.get_vnic(
                self.oci_vnic_attachment.vnic_id).data
        return self._oci_vnic
