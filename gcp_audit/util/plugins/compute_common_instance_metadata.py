from . import Base
import logging

__class_name__ = 'ComputeCommonInstanceMetadata'
logger = logging.getLogger(__name__)


class ComputeCommonInstanceMetadata(Base):
    def get_data(self, project):
        service = self._get_service(service='compute')
        req = service.projects().get(project=project, fields='commonInstanceMetadata/items')

        try:
            metadata = req.execute()['commonInstanceMetadata']['items']
        except:
            metadata = []
        return metadata
