from . import Base
import logging

__class_name__ = 'ContainerClusters'
logger = logging.getLogger(__name__)


class ContainerClusters(Base):
    def get_data(self, project):
        service = self._get_service(service='container')
        req = service.projects().zones().clusters().list(projectId=project, zone='-')

        try:
            res = req.execute()['clusters']
        except:
            res = []

        return res
