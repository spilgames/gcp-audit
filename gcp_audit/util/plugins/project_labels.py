from . import Base
import logging

__class_name__ = 'ProjectLabels'
logger = logging.getLogger(__name__)


class ProjectLabels(Base):
    def get_data(self, project):
        service = self._get_service(service='cloudresourcemanager')
        req = service.projects().get(projectId=project)

        try:
            labels = req.execute()['labels']
            res = []
            for label, value in labels.iteritems():
                res.append({'label': label, 'value': value})
        except:
            res = []

        return res
