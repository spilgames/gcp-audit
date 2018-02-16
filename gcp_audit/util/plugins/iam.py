from . import Base
import logging

__class_name__ = 'Iam'
logger = logging.getLogger(__name__)


class Iam(Base):
    def __init__(self, gcp_audit):
        Base.__init__(self, gcp_audit)
        self._cache = {
            'project': {},
            'folder': {},
            'organization': {},
        }

    def get_data(self, project):
        def member_obj(member):
            (member_type, member_id) = member.split(':')
            return {member_type: member_id}

        service = self._get_service(service='cloudresourcemanager')

        res = []
        try:
            merged_roles = {}
            ancestry = service.projects().getAncestry(projectId=project, body={}).execute()['ancestor']
            for ancestor in ancestry[::-1]:
                res_type = ancestor['resourceId']['type']
                res_id = ancestor['resourceId']['id']
                if res_type == 'project':
                    bindings = self._get_project_iam(res_id)
                elif res_type == 'folder':
                    bindings = self._get_folder_iam(res_id)
                elif res_type == 'organization':
                    bindings = self._get_organization_iam(res_id)
                else:
                    bindings = []

                for binding in bindings:
                    role = binding['role']
                    members = binding['members']
                    if role not in merged_roles:
                        merged_roles[role] = set(members)
                    else:
                        merged_roles[role].update(members)

            for (role, members) in merged_roles.items():
                res.append({
                        u'role': role,
                        u'members': [member_obj(member) for member in members],
                    })
        except Exception as e:
            logger.exception(e)
            res = []

        return res

    def _get_project_iam(self, project_id):
        if project_id not in self._cache['project']:
            logger.info('Fetching iam for project %s from api', project_id)
            service = self._get_service(service='cloudresourcemanager')
            res = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            bindings = []
            if 'bindings' in res:
                bindings = res['bindings']
            self._cache['project'][project_id] = bindings
        else:
            logger.info('Fetching iam for project %s from cache', project_id)
        return self._cache['project'][project_id]

    def _get_folder_iam(self, folder_id):
        if folder_id not in self._cache['folder']:
            logger.info('Fetching iam for folder %s from api', folder_id)
            service = self._get_service(service='cloudresourcemanager', version='v2')
            recource_id = 'folders/{}'.format(folder_id)
            res = service.folders().getIamPolicy(resource=recource_id, body={}).execute()
            bindings = []
            if 'bindings' in res:
                bindings = res['bindings']
            self._cache['folder'][folder_id] = bindings
        else:
            logger.info('Fetching iam for folder %s from cache', folder_id)
        return self._cache['folder'][folder_id]

    def _get_organization_iam(self, organization_id):
        if organization_id not in self._cache['organization']:
            logger.info('Fetching iam for organization %s from api', organization_id)
            service = self._get_service(service='cloudresourcemanager')
            recource_id = 'organizations/{}'.format(organization_id)
            res = service.organizations().getIamPolicy(resource=recource_id, body={}).execute()
            bindings = []
            if 'bindings' in res:
                bindings = res['bindings']
            self._cache['organization'][organization_id] = bindings
        else:
            logger.info('Fetching iam for organization %s from cache', organization_id)
        return self._cache['organization'][organization_id]
