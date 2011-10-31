from nose.tools import *
from fakeldap import MockLDAP

import unittest


tree = {
    "cn=admin,dc=30loops,dc=net": {
            "userPassword": "ldaptest"
            }
}


class TestLdapOperations(unittest.TestCase):
    def setUp(self):
        self.mock_ldap = MockLDAP(tree)

    def test_add_s_operation(self):
        """Test the addition of records to the mock ldap object."""
        record = [
                ('uid', 'crito'),
                ('userPassword', 'secret'),
                ]
        eq_((105,[],1,[]), self.mock_ldap.add_s(
                    "uid=crito,ou=people,dc=30loops,dc=net", record
                    ))

        directory = {
                "cn=admin,dc=30loops,dc=net": {"userPassword": "ldaptest"},
                "uid=crito,ou=people,dc=30loops,dc=net": {
                    "uid": "crito", "userPassword": "secret"}
                }
        eq_(directory, self.mock_ldap.directory)

        record = [
                ('uid', 'bas'),
                ('userPassword', 'secret'),
                ]
        eq_((105,[],2,[]), self.mock_ldap.add_s(
                    "uid=bas,ou=people,dc=30loops,dc=net", record
                    ))

