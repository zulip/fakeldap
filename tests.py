from fakeldap import MockLDAP, _tupelize
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

    def test_tupelize(self):

        # one level
        self.assertEqual('string', _tupelize('string'))
        self.assertEqual((1,2,3), _tupelize([1,2,3]))
        self.assertEqual( (('a', 1), ('b', 2), ('c', 3),), _tupelize( {'a': 1, 'b': 2, 'c': 3, } ))

        # recursively and complex
        self.assertEqual( ('string', (1,2,3,), (('a', 1), ('b', 2), ('c', 3),)), _tupelize( ['string', [1,2,3], {'a': 1, 'b': 2, 'c': 3, }, ] ))

    def test_simple_bind_s_operation(self):
        """Try to bind a user."""
        # Make a valid bind
        self.assertEqual(
            (97,[]),
            self.mock_ldap.simple_bind_s("cn=admin,dc=30loops,dc=net", "ldaptest")
        )

        # Supply the wrong password
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            self.mock_ldap.simple_bind_s("cn=admin,dc=30loops,dc=net", "wrong")

    def test_add_s_operation(self):
        """Test the addition of records to the mock ldap object."""
        record = [
                ('uid', 'crito'),
                ('userPassword', 'secret'),
                ]
        self.assertEqual((105,[],1,[]), self.mock_ldap.add_s(
                    "uid=crito,ou=people,dc=30loops,dc=net", record
                    ))

        directory = {
                "cn=admin,dc=30loops,dc=net": {"userPassword": "ldaptest"},
                "uid=crito,ou=people,dc=30loops,dc=net": {
                    "uid": "crito", "userPassword": "secret"}
                }
        self.assertEqual(directory, self.mock_ldap.directory)

        record = [
                ('uid', 'bas'),
                ('userPassword', 'secret'),
                ]
        self.assertEqual((105,[],2,[]), self.mock_ldap.add_s(
                    "uid=bas,ou=people,dc=30loops,dc=net", record
                    ))

    def test_modify_s_operation(self):
        """Test the modification of records in the mock ldap object."""
        directory = {
            "ou=groups,dc=30loops,dc=net": { "ou": ("groups",) },
            "cn=users,ou=groups,dc=30loops,dc=net": {
                    "cn": ("users",),
                    "memberUid": ( "john", "jack", "john2", "sam", "jim", "ben", ),
                    },
        }
        self.mock_ldap = MockLDAP(directory)

        modlist_MOD_ADD_non_present_attrdesc = [ (self.mock_ldap.MOD_ADD, 'description', 'Group of all users', ), ]
        self.assertEqual((103,[]), self.mock_ldap.modify_s("cn=users,ou=groups,dc=30loops,dc=net", modlist_MOD_ADD_non_present_attrdesc))

        self.assertEqual(self.mock_ldap.directory["cn=users,ou=groups,dc=30loops,dc=net"],
            {
                "cn": ("users",),
                "description": ('Group of all users',),
                "memberUid": ("john", "jack", "john2", "sam", "jim", "ben", ),
            }
        )

        modlist_MOD_ADD_already_present_attrdesc = [ (self.mock_ldap.MOD_ADD, 'description', 'but not all users on the entire internet', ), ]
        self.assertEqual((103,[]), self.mock_ldap.modify_s("cn=users,ou=groups,dc=30loops,dc=net", modlist_MOD_ADD_already_present_attrdesc))

        self.assertEqual(self.mock_ldap.directory["cn=users,ou=groups,dc=30loops,dc=net"],
            {
                "cn": ("users",),
                "description": ('Group of all users', 'but not all users on the entire internet',),
                "memberUid": ("john", "jack", "john2", "sam", "jim", "ben", ),
            }
        )

        modlist_MOD_DELETE_entire_attrdesc = [ (self.mock_ldap.MOD_DELETE, 'description', None, ), ]
        self.assertEqual((103,[]), self.mock_ldap.modify_s("cn=users,ou=groups,dc=30loops,dc=net", modlist_MOD_DELETE_entire_attrdesc))

        self.assertEqual(self.mock_ldap.directory["cn=users,ou=groups,dc=30loops,dc=net"],
            {
                "cn": ("users",),
                "memberUid": ("john", "jack", "john2", "sam", "jim", "ben", ),
            }
        )

        modlist_MOD_DELETE_one_value = [ (self.mock_ldap.MOD_DELETE, 'memberUid', 'jack', ), ]
        self.assertEqual((103,[]), self.mock_ldap.modify_s("cn=users,ou=groups,dc=30loops,dc=net", modlist_MOD_DELETE_one_value))

        self.assertEqual(self.mock_ldap.directory["cn=users,ou=groups,dc=30loops,dc=net"],
            {
                "cn": ("users",),
                "memberUid": ("john", "john2", "sam", "jim", "ben", ),
            }
        )

        modlist_MOD_DELETE_several_values = [ (self.mock_ldap.MOD_DELETE, 'memberUid', ['john', 'sam', 'ben'], ), ]
        self.assertEqual((103,[]), self.mock_ldap.modify_s("cn=users,ou=groups,dc=30loops,dc=net", modlist_MOD_DELETE_several_values))

        self.assertEqual(self.mock_ldap.directory["cn=users,ou=groups,dc=30loops,dc=net"],
            {
                "cn": ("users",),
                "memberUid": ("john2", "jim", ),
            }
        )

        modlist_MOD_REPLACE_all_different = [ (self.mock_ldap.MOD_REPLACE, 'memberUid', ['wilhelm', 'bernd', 'karl'], ), ]
        self.assertEqual((103,[]), self.mock_ldap.modify_s("cn=users,ou=groups,dc=30loops,dc=net", modlist_MOD_REPLACE_all_different))

        self.assertEqual(self.mock_ldap.directory["cn=users,ou=groups,dc=30loops,dc=net"],
            {
                "cn": ("users",),
                "memberUid": ("wilhelm", "bernd", "karl", ),
            }
        )

    def test_search_s_base(self):
        result = self.mock_ldap.search_s("cn=admin,dc=30loops,dc=net", ldap.SCOPE_BASE)
        self.assertEqual(result, [('cn=admin,dc=30loops,dc=net', {'userPassword': 'ldaptest'})])

    def test_search_s_onelevel(self):
        directory = {
            "ou=users,dc=30loops,dc=net": { "ou": "users" },
            "ou=groups,dc=30loops,dc=net": { "ou": "groups" },
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
                    },
            "cn=group1,ou=groups,dc=30loops,dc=net": {
                    "objectClass": "groupOfUniqueNames",
                    "uniqueMember": "cn=john2,ou=users,dc=30loops,dc=net"
                    }
        }
        self.mock_ldap = MockLDAP(directory)

        result = self.mock_ldap.search_s("dc=30loops,dc=net", ldap.SCOPE_ONELEVEL,
                                         "(mail=jack@example.com)")
        # The search is one-level, so the above should return no results:
        self.assertEqual(result, [])

        result = self.mock_ldap.search_s("ou=users,dc=30loops,dc=net", ldap.SCOPE_ONELEVEL,
                                         "(mail=jack@example.com)")
        self.assertEqual(
            result,
            [('cn=jack,ou=users,dc=30loops,dc=net',
             {'userPassword': ['ldaptest'], 'mail': ['jack@example.com']})]
        )

        result = self.mock_ldap.search_s("ou=users,dc=30loops,dc=net", ldap.SCOPE_ONELEVEL,
                                         "(mail=john@example.com)")
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

        # search for both johns using anded conditions:
        result = self.mock_ldap.search_s("ou=users,dc=30loops,dc=net", ldap.SCOPE_ONELEVEL,
                                          "(&(mail=john@example.com)(userPassword=ldaptest))")

        self.assertIn(
            ('cn=john,ou=users,dc=30loops,dc=net',{'mail': 'john@example.com', 'userPassword': 'ldaptest'}),
            result
        )
        self.assertIn(
            ('cn=john2,ou=users,dc=30loops,dc=net',{'mail': 'john@example.com', 'userPassword': 'ldaptest'}),
            result
        )

        # search for both johns using anded conditions:
        result = self.mock_ldap.search_s("ou=groups,dc=30loops,dc=net", ldap.SCOPE_ONELEVEL,
                                          "(&(objectClass=groupOfUniqueNames)(uniqueMember=cn=john2,ou=users,dc=30loops,dc=net))")

        self.assertIn(
            ('cn=group1,ou=groups,dc=30loops,dc=net',{'objectClass': 'groupOfUniqueNames', 'uniqueMember': 'cn=john2,ou=users,dc=30loops,dc=net'}),
            result
        )
