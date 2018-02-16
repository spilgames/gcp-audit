from buckets import Buckets
import logging

__class_name__ = 'BucketObjects'
logger = logging.getLogger(__name__)


class BucketObjects(Buckets):
    def get_data(self, project):
        res = []
        buckets = self._get_buckets(project)
        for bucket in buckets:
            res.extend(self._get_default_access_controls(project, bucket["name"]))
        return res

    def _get_default_access_controls(self, project, bucket):
        service = self._get_service(service='storage')
        req = service.defaultObjectAccessControls().list(bucket=bucket)
        try:
            res = req.execute()['items']
        except:
            res = []

        return res
