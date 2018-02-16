from . import Base
import logging

__class_name__ = 'Buckets'
logger = logging.getLogger(__name__)


class Buckets(Base):
    def get_data(self, project):
        res = []
        buckets = self._get_buckets(project)
        for bucket in buckets:
            res += self._get_acls_for_bucket(project, bucket['name'])
        return res

    def _get_buckets(self, project):
        key = 'list_{project}'.format(project=project)
        buckets = self._get_cache('buckets', key)
        if not buckets:
            service = self._get_service(service='storage')
            req = service.buckets().list(project=project)
            try:
                buckets = req.execute()['items']
            except:
                buckets = []
            self._set_cache('buckets', key, buckets)
        return buckets

    def _get_acls_for_bucket(self, project, bucket):
        service = self._get_service(service='storage')
        req = service.bucketAccessControls().list(bucket=bucket)

        try:
            res = req.execute()['items']
        except:
            res = []

        return res
