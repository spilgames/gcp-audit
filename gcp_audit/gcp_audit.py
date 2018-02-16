#!/usr/bin/env python

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

import json
import os
from argparse import ArgumentParser
import util.gcp_audit as gcp_audit
import logging

logging.basicConfig(level=logging.INFO)
logging.getLogger('googleapiclient').setLevel(logging.FATAL)
logging.getLogger('oauth2client').setLevel(logging.FATAL)


def parse_options():
    def comma_split(str):
        return str.split(',')

    parser = ArgumentParser(description='A tool for auditing security \
                                         properties of GCP projects.',
                            epilog='gcp-audit needs a valid key for an account \
                                    with audit capabilities for the projects \
                                    in scope in order to work. This needs \
                                    to be set either via the \
                                    GOOGLE_APPLICATION_CREDENTIALS \
                                    environment variable, \
                                    or via the -k parameter.')
    parser.add_argument('-c', '--checks',
                        help='json file to read the checks from')
    parser.add_argument('-k', '--keyfile',
                        help="keyfile to use for GCP credentials")
    parser.add_argument('-o', '--output',
                        help='file to output results to',
                        default='results.json')
    parser.add_argument('-r', '--rules',
                        help='directory containing the rules definitions',
                        default=os.path.join(os.path.dirname(__file__), "rules"))
    parser.add_argument('-p', '--projects',
                        help='comma separated list of GCP projects to audit',
                        type=comma_split)

    options = parser.parse_args()

    return options

if __name__ == "__main__":
    default_checks = {
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
    options = parse_options()

    if options.checks:
        with open(options.checks) as f:
            checks = json.load(f)
    else:
        checks = default_checks

    audit = gcp_audit.GcpAudit(checks=checks, keyfile=options.keyfile, projects=options.projects, rules_dir=options.rules)
    result = audit.audit()
    with open(options.output, 'w') as f:
        f.write(json.dumps(result, sort_keys=True))

