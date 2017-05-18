import unittest

import gcp_audit


class TestApplyRuleFilter(unittest.TestCase):

    def test_firewall(self):

        obj = {u'kind': u'compute#firewall',
               u'network': u'https://www.googleapis.com/compute/v1/projects/gffgjfghdffdsgfjghk/global/networks/default',
               u'sourceRanges': [u'0.0.0.0/0'], u'name': u'default-allow-ssh',
               u'allowed': [{u'IPProtocol': u'tcp', u'ports': [u'22']}], u'creationTimestamp': u'2017-05-03T04:47:32.052-07:00',
               u'id': u'3326097056541736379',
               u'selfLink': u'https://www.googleapis.com/compute/v1/projects/gffgjfghdffdsgfjghk/global/firewalls/default-allow-ssh',
               u'description': u'Allow SSH from anywhere'}

        filters = [
            {
                u'filter': {u'sourceRanges': u'0.0.0.0/0', u'allowed': [{u'IPProtocol': u'tcp|udp', u'ports': u'.+'}]},
                u'matchtype': u'regex'
            },
            {
                u'filter': {u'targetTags': u'eq 0'},
                u'matchtype': u'count'
            }
        ]

        filtercondition = "and"

        self.assertTrue(gcp_audit.apply_rule_filters(
            obj, filters, filtercondition))

    def test_cloudSQLNoAuthorizedNetworks(self):

        obj = {u'kind': u'sql#instance', u'name': u'fdgdsgfdhdfh-instance',
               u'settings': {u'kind': u'sql#settings', u'dataDiskType': u'PD_HDD',
                             u'maintenanceWindow': {u'kind': u'sql#maintenanceWindow', u'day': 0, u'hour': 0},
                             u'authorizedGaeApplications': [], u'activationPolicy': u'ALWAYS',
                             u'backupConfiguration': {u'kind': u'sql#backupConfiguration', u'enabled': True,
                                                      u'binaryLogEnabled': True, u'startTime': u'07:00'}, u'ipConfiguration': {u'ipv4Enabled': True,
                                                                                                                               u'authorizedNetworks': []},
                             u'pricingPlan': u'PER_USE',
                             u'replicationType': u'SYNCHRONOUS',
                             u'storageAutoResizeLimit': u'0', u'tier': u'db-n1-standard-1', u'settingsVersion': u'1',
                             u'storageAutoResize': True, u'locationPreference': {u'kind': u'sql#locationPreference',
                                                                                 u'zone': u'europe-west1-d'}, u'dataDiskSizeGb': u'10'}, u'region': u'europe-west1',
               u'backendType': u'SECOND_GEN', u'project': u'haadgdhfdhfgj', u'state': u'RUNNABLE',
               u'etag': u'"asdsdgfsdgsdg"', u'serviceAccountEmailAddress': u'fdhdsfsdgsdfhdg',
               u'serverCaCert': {u'certSerialNumber': u'0', u'kind': u'sql#sslCert', u'sha1Fingerprint': u'fdhdfgdsfsdgdfhdfg',
                                 u'commonName': u'C=US,O=Google\\, Inc,CN=Google Cloud SQL Server CA', u'instance': u'fdgdsgfdhdfh-instance',
                                 u'cert': u'-----BEGIN CERTIFICATE-----\nxxx\n-----END CERTIFICATE-----', u'expirationTime': u'2019-03-23T10:07:36.954Z',
                                 u'createTime': u'2017-03-23T10:06:36.954Z'}, u'ipAddresses': [{u'type': u'PRIMARY', u'ipAddress': u'a.b.c.d'}],
               u'connectionName': u'sasdgsdgdh:dfhfgjhfdjfj:fdgdsgfdhdfh-instance', u'databaseVersion': u'MYSQL_5_7',
               u'instanceType': u'CLOUD_SQL_INSTANCE', u'selfLink': u'https://www.googleapis.com/sql/v1beta4/projects/haadgdhfdhfgj/instances/fdgdsgfdhdfh-instance'}

        filters = [{u'filter': {u'settings': {u'ipConfiguration': {
            u'authorizedNetworks': [{u'value': u'0.0.0.0/0'}]}}}, u'matchtype': u'exact'}]

        filtercondition = "and"

        self.assertFalse(gcp_audit.apply_rule_filters(
            obj, filters, filtercondition))

    def test_cloudSQLAuthorizedNetworks(self):

        obj = {u'kind': u'sql#instance', u'name': u'fdgdsgfdhdfh-instance',
               u'settings': {u'kind': u'sql#settings', u'dataDiskType': u'PD_HDD',
                             u'maintenanceWindow': {u'kind': u'sql#maintenanceWindow', u'day': 0, u'hour': 0},
                             u'authorizedGaeApplications': [], u'activationPolicy': u'ALWAYS',
                             u'backupConfiguration': {u'kind': u'sql#backupConfiguration', u'enabled': True,
                                                      u'binaryLogEnabled': True, u'startTime': u'07:00'}, u'ipConfiguration': {u'ipv4Enabled': True,
                                                                                                                               u'authorizedNetworks': [{"value":"1.2.3.4/32"}]},
                             u'pricingPlan': u'PER_USE',
                             u'replicationType': u'SYNCHRONOUS',
                             u'storageAutoResizeLimit': u'0', u'tier': u'db-n1-standard-1', u'settingsVersion': u'1',
                             u'storageAutoResize': True, u'locationPreference': {u'kind': u'sql#locationPreference',
                                                                                 u'zone': u'europe-west1-d'}, u'dataDiskSizeGb': u'10'}, u'region': u'europe-west1',
               u'backendType': u'SECOND_GEN', u'project': u'hgdsfasddassdh', u'state': u'RUNNABLE',
               u'etag': u'"asdsdgfsdgsdg"', u'serviceAccountEmailAddress': u'fdhdsfsdgsdfhdg',
               u'serverCaCert': {u'certSerialNumber': u'0', u'kind': u'sql#sslCert', u'sha1Fingerprint': u'fdhdfgdsfsdgdfhdfg',
                                 u'commonName': u'C=US,O=Google\\, Inc,CN=Google Cloud SQL Server CA', u'instance': u'fdgdsgfdhdfh-instance',
                                 u'cert': u'-----BEGIN CERTIFICATE-----\nxxx\n-----END CERTIFICATE-----', u'expirationTime': u'2019-03-23T10:07:36.954Z',
                                 u'createTime': u'2017-03-23T10:06:36.954Z'}, u'ipAddresses': [{u'type': u'PRIMARY', u'ipAddress': u'a.b.c.d'}],
               u'connectionName': u'sasdgsdgdh:dfhfgjhfdjfj:fdgdsgfdhdfh-instance', u'databaseVersion': u'MYSQL_5_7',
               u'instanceType': u'CLOUD_SQL_INSTANCE', u'selfLink': u'https://www.googleapis.com/sql/v1beta4/projects/hgdsfasddassdh/instances/fdgdsgfdhdfh-instance'}

        filters = [{u'filter': {u'settings': {u'ipConfiguration': {
            u'authorizedNetworks': [{u'value': u'0.0.0.0/0'}]}}}, u'matchtype': u'exact'}]

        filtercondition = "and"

        self.assertFalse(gcp_audit.apply_rule_filters(
            obj, filters, filtercondition))

    def test_cloudSQLOpen(self):

        obj = {u'kind': u'sql#instance', u'name': u'fdgdsgfdhdfh-instance',
               u'settings': {u'kind': u'sql#settings', u'dataDiskType': u'PD_HDD',
                             u'maintenanceWindow': {u'kind': u'sql#maintenanceWindow', u'day': 0, u'hour': 0},
                             u'authorizedGaeApplications': [], u'activationPolicy': u'ALWAYS',
                             u'backupConfiguration': {u'kind': u'sql#backupConfiguration', u'enabled': True,
                                                      u'binaryLogEnabled': True, u'startTime': u'07:00'}, u'ipConfiguration': {u'ipv4Enabled': True,
                                                                                                                               u'authorizedNetworks': [{"value":"0.0.0.0/0"}]},
                             u'pricingPlan': u'PER_USE',
                             u'replicationType': u'SYNCHRONOUS',
                             u'storageAutoResizeLimit': u'0', u'tier': u'db-n1-standard-1', u'settingsVersion': u'1',
                             u'storageAutoResize': True, u'locationPreference': {u'kind': u'sql#locationPreference',
                                                                                 u'zone': u'europe-west1-d'}, u'dataDiskSizeGb': u'10'}, u'region': u'europe-west1',
               u'backendType': u'SECOND_GEN', u'project': u'dgdfhdfhdfjdfjdfhfd', u'state': u'RUNNABLE',
               u'etag': u'"asdsdgfsdgsdg"', u'serviceAccountEmailAddress': u'fdhdsfsdgsdfhdg',
               u'serverCaCert': {u'certSerialNumber': u'0', u'kind': u'sql#sslCert', u'sha1Fingerprint': u'fdhdfgdsfsdgdfhdfg',
                                 u'commonName': u'C=US,O=Google\\, Inc,CN=Google Cloud SQL Server CA', u'instance': u'fdgdsgfdhdfh-instance',
                                 u'cert': u'-----BEGIN CERTIFICATE-----\nxxx\n-----END CERTIFICATE-----', u'expirationTime': u'2019-03-23T10:07:36.954Z',
                                 u'createTime': u'2017-03-23T10:06:36.954Z'}, u'ipAddresses': [{u'type': u'PRIMARY', u'ipAddress': u'a.b.c.d'}],
               u'connectionName': u'sasdgsdgdh:dfhfgjhfdjfj:fdgdsgfdhdfh-instance', u'databaseVersion': u'MYSQL_5_7',
               u'instanceType': u'CLOUD_SQL_INSTANCE', u'selfLink': u'https://www.googleapis.com/sql/v1beta4/projects/dgdfhdfhdfjdfjdfhfd/instances/fdgdsgfdhdfh-instance'}

        filters = [{u'filter': {u'settings': {u'ipConfiguration': {
            u'authorizedNetworks': [{u'value': u'0.0.0.0/0'}]}}}, u'matchtype': u'exact'}]

        filtercondition = "and"

        self.assertTrue(gcp_audit.apply_rule_filters(
            obj, filters, filtercondition))


if __name__ == '__main__':
    unittest.main()
