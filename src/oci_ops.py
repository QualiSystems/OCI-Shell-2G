import oci


class OciOperations(object):
    def __init__(self, resource_config):
        config = {
            "user": resource_config.api_user_id,
            "key_file": resource_config.api_key_file_path,
            "pass_phrase": resource_config.api_key_passphrase,
            "fingerprint": resource_config.api_key_file_fingerprint,
            "tenancy": resource_config.tenant_id,
            "region": resource_config.region
        }
        self.compute_client = oci.core.ComputeClient(config)
        self.network_client = oci.core.VirtualNetworkClient(config)
        self.storage_client = oci.core.BlockstorageClient(config)
        self.identity_client = oci.identity.IdentityClient(config)
        self.net_client_ops = oci.core.VirtualNetworkClientCompositeOperations(self.network_client)
