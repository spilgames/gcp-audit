class Base:
    def __init__(self, gcp_audit):
        self._gcp_audit = gcp_audit

    def _get_service(self, service, version='v1'):
        return self._gcp_audit._get_service(service, version)

    def _get_cache(self, namespace, key, default=None):
        return self._gcp_audit._get_plugin_cache(namespace, key, default)

    def _set_cache(self, namespace, key, value):
        self._gcp_audit._set_plugin_cache(namespace, key, value)

    def get_data(self, project):
        raise NotImplemented()
