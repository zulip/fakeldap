from nose.tools import *
from fakeldap import MockLDAP
import ldap

import unittest


directory = {
    "cn=admin,dc=30loops,dc=net": {
        "userPassword": "ldaptest"
    }
}


class TestLdapOperations(unittest.TestCase):
    def setUp(self):
        self.mock_ldap = MockLDAP(directory)

    def tearDown(self):
        self.mock_ldap.reset()

    def test_simple_bind_s_operation(self):
        """Try to bind a user."""
        # Make a valid bind
        eq_(
            (97, []),
            self.mock_ldap.simple_bind_s("cn=admin,dc=30loops,dc=net", "ldaptest")
        )

        # Supply the wrong password
        assert_raises(
            ldap.INVALID_CREDENTIALS,
            self.mock_ldap.simple_bind_s,
            who="cn=admin,dc=30loops,dc=net", cred="wrong"
        )

    def test_add_s_operation(self):
        """Test the addition of records to the mock ldap object."""
        record = [
            ('uid', 'crito'),
            ('userPassword', 'secret'),
        ]
        eq_((105, [], 1, []), self.mock_ldap.add_s(
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
        eq_((105, [], 2, []), self.mock_ldap.add_s(
            "uid=bas,ou=people,dc=30loops,dc=net", record
        ))

    def test_search_s_base(self):
        result = self.mock_ldap.search_s("cn=admin,dc=30loops,dc=net", ldap.SCOPE_BASE)
        self.assertEqual(result, [('cn=admin,dc=30loops,dc=net', {'userPassword': 'ldaptest'})])

    def test_search_s_onelevel(self):
        directory = {
            "ou=users,dc=30loops,dc=net": {"ou": "users"},
            "cn=admin,ou=users,dc=30loops,dc=net": {
                "userPassword": "ldaptest"
            },
            "cn=john,ou=users,dc=30loops,dc=net": {
                "userPassword": "ldaptest",
                "mail": "john@example.com"
            },
            "cn=jack,ou=users,dc=30loops,dc=net": {
                # test [value, ] format here
                "userPassword": ["ldaptest", ],
                "mail": ["jack@example.com", ]
            },
            "cn=john2,ou=users,dc=30loops,dc=net": {
                "userPassword": "ldaptest",
                "mail": "john@example.com"  # same mail as john
            }
        }
        self.mock_ldap = MockLDAP(directory)

        result = self.mock_ldap.search_s(
            "dc=30loops,dc=net",
            ldap.SCOPE_ONELEVEL,
            "(mail=jack@example.com)"
        )
        # The search is one-level, so the above should return no results:
        self.assertEqual(result, [])

        result = self.mock_ldap.search_s(
            "ou=users,dc=30loops,dc=net",
            ldap.SCOPE_ONELEVEL,
            "(mail=jack@example.com)"
        )
        self.assertEqual(
            result,
            [('cn=jack,ou=users,dc=30loops,dc=net',
              {'userPassword': ['ldaptest'], 'mail': ['jack@example.com']})]
        )

        result = self.mock_ldap.search_s(
            "ou=users,dc=30loops,dc=net",
            ldap.SCOPE_ONELEVEL,
            "(mail=john@example.com)"
        )
        self.assertEqual(len(result), 2)
        self.assertIn(
            ('cn=john,ou=users,dc=30loops,dc=net', {'userPassword': 'ldaptest', 'mail': 'john@example.com'}),
            result
        )
        self.assertIn(
            ('cn=john2,ou=users,dc=30loops,dc=net', {'userPassword': 'ldaptest', 'mail': 'john@example.com'}),
            result
        )

        result = self.mock_ldap.search_s("dc=30loops,dc=net", ldap.SCOPE_ONELEVEL,
                                         "(mail=nonexistant@example.com)")
        self.assertEqual(result, [])
