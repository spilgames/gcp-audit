#!/usr/bin/env python

# Based on https://github.com/bolcom/gcp-audit (https://github.com/spotify/gcp-audit)
#
# Original copyright notice:
#
# Copyright (c) 2016-2017 Spotify AB.
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

try:
    import googleapiclient
    import googleapiclient.discovery as discovery
    from googleapiclient.errors import HttpError
except ImportError:
    # allow tests without this dependency
    googleapiclient = None
    discovery = None
    HttpError = None

try:
    from oauth2client.client import GoogleCredentials
except ImportError:
    # allow tests without this dependency
    GoogleCredentials = None

import json
import logging
import os
import yaml
import re
import operator
import importlib


logger = logging.getLogger(__name__)


class GcpAudit():
    def __init__(self, checks=None, keyfile=None, projects=None, rules_dir=None):
        if isinstance(checks, dict):
            self._checks = checks
        else:
            self._checks = {
                'buckets': {
                    'plugin': 'util.plugins.buckets',
                    'descfield': 'bucket'
                },
                'bucket_objects': {
                    'plugin': 'util.plugins.bucket_objects',
                    'descfield': 'entity'
                },
                'cloudsql': {
                    'plugin': 'util.plugins.cloudsql',
                    'descfield': 'name'
                },
                'firewalls': {
                    'plugin': 'util.plugins.firewalls',
                    'descfield': 'name'
                },
                'iam': {
                    'plugin': 'util.plugins.iam',
                    'descfield': 'role'
                }
            }

        self._plugin_cache = {}
        self._loadplugins()
        self._loadrules(rules_dir)

        self._keyfile = keyfile
        self._projects = projects
        self._cache = {
            'service': {},
        }
        self._output = {}

    def audit(self):
        try:
            self._set_env_credentials()
            if not self._projects:
                self._projects = self._list_all_available_projects()

            for project in self._projects:
                logger.info('Auditing project %s', project)
                for name, check in self._checks.iteritems():
                    try:
                        logger.debug("loading data")
                        res = self._plugins[name].get_data(project)
                        logger.debug("data loaded %s", res)
                        self._apply_rules(name, res, check['descfield'], project)
                    except Exception as e:
                        logger.exception(e)
                    except HttpError:
                        logger.error('Permission denied?')

            logger.info('Done')
        except Exception as e:
            logger.exception(e)
        finally:
            self._restore_env_credentials()

        return self._output

    def _set_env_credentials(self):
        if self._keyfile:
            if 'GOOGLE_APPLICATION_CREDENTIALS' in os.environ:
                self._original_env_credentials = os.environ['GOOGLE_APPLICATION_CREDENTIALS']
            else:
                self._original_env_credentials = None
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self._keyfile

    def _restore_env_credentials(self):
        if self._keyfile:
            if self._original_env_credentials:
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self._original_env_credentials
            else:
                os.unsetenv('GOOGLE_APPLICATION_CREDENTIALS')

    def _list_all_available_projects(self):
        """Get all projects that the credentials have access to."""
        projects = []
        page_token = None

        while True:
            resp = self._get_service('cloudresourcemanager').projects() \
                .list(pageSize=250, pageToken=page_token).execute()

            projects += [x['projectId'] for x in resp['projects']]

            page_token = resp.get('nextPageToken', None)
            if not page_token:
                break
        return projects

    def _get_service(self, service, version='v1'):
        service_key = '{service}_{version}'.format(service=service, version=version)
        if service_key not in self._cache['service']:
            credentials = GoogleCredentials.get_application_default()
            self._cache['service'][service_key] = discovery.build(service, version, credentials=credentials)
        return self._cache['service'][service_key]

    def _get_plugin_cache(self, namespace, key, default=None):
        if namespace in self._plugin_cache:
            if key in self._plugin_cache[namespace]:
                return self._plugin_cache[namespace][key]
        return default

    def _set_plugin_cache(self, namespace, key, value):
        if namespace not in self._plugin_cache:
            self._plugin_cache[namespace] = {}
        self._plugin_cache[namespace][key] = value

    def _loadplugins(self):
        self._plugins = {}
        for name, check in self._checks.iteritems():
            plugin = check['plugin']
            module = importlib.import_module(plugin)
            clss = getattr(module, module.__class_name__)
            self._plugins[name] = clss(self)

    def _loadrules(self, rules_dir):
        self._rules = {}
        if not rules_dir:
            rules_dir = os.path.join(os.path.dirname(__file__), "rules")

        for ruletype in self._checks.keys():
            rules = []
            path = os.path.join(rules_dir, ruletype)
            for file in os.listdir(path):
                with open("%s/%s" % (path, file)) as rulefile:
                    if file.endswith(".json"):
                        rule = json.load(rulefile)
                    elif file.endswith(".yaml"):
                        rule = yaml.safe_load(rulefile)
                    else:
                        raise "Unknown rule format"
                    rules.append(rule)
                    logger.debug("loaded rule %s/%s", ruletype, file)
            self._rules[ruletype] = rules

    def _apply_rules(self, ruletype, gcpobjects, descfield, project):
        rules = self._rules[ruletype]
        for rule in rules:
            match_type = 'any'
            if 'match_type' in rule:
                if rule['match_type'] in ['all', 'none', 'any']:
                    match_type = rule['match_type']

            matches = []
            for obj in gcpobjects:

                if 'filtercondition' in rule:
                    res = self._apply_rule_filters(obj, rule['filters'],
                                                   rule['filtercondition'])
                else:
                    res = self._apply_rule_filters(obj, rule['filters'])
                if res:
                    matches.append(
                        {
                            'match_type': match_type,
                            'object': obj[descfield],
                            'rule': rule['name'],
                            'details': obj,
                        })

            has_match = False
            if match_type == 'any':
                has_match = len(matches) > 0
            elif match_type == 'none':
                has_match = len(matches) == 0
            elif match_type == 'all':
                has_match = len(matches) == len(gcpobjects)

            if has_match:
                if project not in self._output:
                    self._output[project] = {}
                if ruletype not in self._output[project]:
                    self._output[project][ruletype] = []

                if match_type == 'none':
                    logger.error("no object matches rule '%s/%s' in project %s", ruletype, rule['name'], project)
                    self._output[project][ruletype].append({
                            'match_type': match_type,
                            'rule': rule['name'],
                        })
                else:
                    for match in matches:
                        desc = match['object']
                        logger.error("object '%s/%s/%s' matches rule '%s'", project, ruletype, desc, rule['name'])
                        self._output[project][ruletype].append(match)

    def _apply_rule_filters(self, obj, filters, filtercondition='and'):
        res = True
        for f in filters:
            if 'listcondition' in f:
                res = self._filterobject(obj,
                                         f['filter'],
                                         f['matchtype'],
                                         f['listcondition'])
            else:
                res = self._filterobject(obj, f['filter'], f['matchtype'])

            if ((filtercondition == 'or' and res) or
               (filtercondition == 'and' and not res)):
                break
        return res

    def _filterobject(self, event, filter, matchtype, listcondition="or"):
        match = True

        if isinstance(filter, dict):
            for k, v in filter.iteritems():
                if k in event:
                    if isinstance(v, dict):
                        match = self._filterobject(event[k], v, matchtype, listcondition)
                    elif isinstance(v, list) and isinstance(event[k], list):
                        match = self._filterobject(event[k], v, matchtype, listcondition)
                    else:
                        # Match filter string against object array
                        if isinstance(event[k], list):
                            for e in event[k]:
                                match = self._filterobject(e, v, matchtype)
                                if match:
                                    break
                        # Match filter string against object string, int, bool
                        else:
                            match = self._matchstr(event[k], v, matchtype)
                else:
                    # For count checks, handle a missing key
                    # as if the key were an empty list
                    if matchtype == "count":
                        match = self._matchstr([], v, matchtype)
                    else:
                        match = False

                if not match:
                    break
        elif isinstance(filter, list) and isinstance(event, list):
            # empty event, means no hit
            if len(event) == 0:
                match = False
            else:
                for f in filter:
                    for e in event:
                        match = self._filterobject(e, f, matchtype, listcondition)
                        if ((listcondition == 'or' and match) or
                                (listcondition == 'and' and not match)):
                            break
        elif isinstance(filter, list):
            for v in filter:
                match = self._filterobject(event, v, matchtype, listcondition)
                if ((listcondition == 'or' and match) or
                        (listcondition == 'and' and not match)):
                    break
        elif isinstance(filter, basestring):
            match = self._matchstr(event, filter, matchtype)
        else:
            raise "ERROR, unknown object encountered"
        return match


    def _matchstr(self, estr, fstr, matchtype):
        if matchtype == 'count' or matchtype == 'numeric':
            ops = {"lt": operator.lt,
                   "gt": operator.gt,
                   "eq": operator.eq}

            op, val = fstr.split()
            val = int(val)

        if matchtype == 'exact':
            match = (fstr == estr)
        elif matchtype == 'partial':
            match = estr.find(fstr)
        elif matchtype == 'regex':
            match = (re.search(fstr, estr) is not None)
        elif matchtype == 'numeric':
            match = isinstance(estr, (int, long) and ops[op](estr, val))
        elif matchtype == 'count':
            # All other objects than lists are single objects
            if isinstance(estr, list):
                objlen = len(estr)
            else:
                objlen = 1

            match = ops[op](objlen, val)
        else:
            raise "ERROR: unknown mode"

        return match
