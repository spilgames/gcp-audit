from . import Base
import logging

__class_name__ = 'Firewalls'
logger = logging.getLogger(__name__)


class Firewalls(Base):
    def get_data(self, project):
        service = self._get_service(service='sqladmin', version='v1beta4')
        req = service.instances().list(project=project)

        try:
            res = req.execute()['items']
        except:
            res = []

        return res
