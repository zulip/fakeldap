========
fakeldap
========

The goal of this module is to provide a simple way to mock ldap backend servers
for your unittests. It makes it possible to define upfront a set of directory
entries that can be queried or set fixed return values to ldap queries. It acts
as a drop in replacement for the ``LDAPObject`` class of the python-ldap
module. It implements a subset of the allowed methods of this class.

This module implements the ``MockLDAP`` class that functions both as the
``LDAPObject`` as well as the ldap module. Most of the code and design has been
taken from Peter Sagerson's excellent django-auth-ldap_ module.

.. _django-auth-ldap: https://bitbucket.org/psagers/django-auth-ldap/wiki/Home

Installation
============

Get and install the code::

    $ git clone git://github.com/30loops/fakeldap.git
    $ cd fakeldap
    $ python setup.py install

If you want, you can run the tests::

    $ python setup.py nosetests

Usage
=====

.. note::

    This code is still experimental and not very tested as of yet. So is the
    documentation
    
The ``MockLDAP`` class replaces the ``LDAPObject`` of the python-ldap module.
The easiest way to use it, is to overwrite ``ldap.initialize`` to return
``MockLDAP`` instead of ``LDAPObject``. The example below uses Michael Foord's
Mock_ library to achieve that::

    import unittest
    from mock import patch
    from fakeldap import MockLDAP


    _mock_ldap = MockLDAP()

    class YourTestCase(unittest.TestCase):
        def setUp(self):
            # Patch where the ldap library is used:
            self.ldap_patcher = patch('app.module.ldap.initialize')
            self.mock_ldap = self.ldap_patcher.start()
            self.mock_ldap.return_value = _mock_ldap

        def tearDown(self):
            _mock_ldap.reset()
            self.mock_ldap.stop()

The mock ldap object implements the following ldap operations:

- simple_bind_s
- search_s
- compare_s
- modify_s
- delete_s
- add_s
- rename_s

This is an example how to use ``MockLDAP`` with fixed return values::

    def test_some_ldap_group_stuff(self):
        # Define the expected return value for the ldap operation
        return_value = ("cn=testgroup,ou=group,dc=30loops,dc=net", {
            'objectClass': ['posixGroup'],
            'cn': 'testgroup',
            'gidNumber': '2030',
        })

        # Register a return value with the MockLDAP object
        _mock_ldap.set_return_value('add_s',
            ("cn=testgroup,ou=groups,dc=30loops,dc=net", (
                ('objectClass', ('posixGroup')),
                ('cn', 'testgroup'),
                ('gidNumber', '2030'))),
            (105,[], 10, []))

        # Run your actual code, this is just an example
        group_manager = GroupManager()
        result = group_manager.add("testgroup")

        # assert that the return value of your method and of the MockLDAP
        # are as expected, here using python-nose's eq() test tool:
        eq_(return_value, result)

        # Each actual ldap call your software makes gets recorded. You could
        # prepare a list of calls that you expect to be issued and compare it:
        called_records = []

        called_records.append(('simple_bind_s',
            {'who': 'cn=admin,dc=30loops,dc=net', 'cred': 'ldaptest'}))

        called_records.append(('add_s', {
            'dn': 'cn=testgroup,ou=groups,dc=30loops,dc=net",
            'record': [
                ('objectClass', ['posixGroup']),
                ('gidNumber', '2030'),
                ('cn', 'testgroup'),
                ]}))

        # And again test the expected behaviour
        eq_(called_records, _mock_ldap.ldap_methods_called_with_arguments())

Besides of fixing return values for specific calls, you can also imitate a full
ldap server with a directory of entries::

    # Create an instance of MockLDAP with a preset directory
    tree = {
        "cn=admin,dc=30loops,dc=net": {
                "userPassword": "ldaptest"
        }
    }
    mock_ldap = MockLDAP(tree) 

    record = [
        ('uid', 'crito'),
        ('userPassword', 'secret'),
    ]
    # The return value I expect when I add another record to the directory
    eq_(
        (105,[],1,[]),
        mock_ldap.add_s("uid=crito,ou=people,dc=30loops,dc=net", record)
    )

    # The expected directory
    directory = {
        "cn=admin,dc=30loops,dc=net": {"userPassword": "ldaptest"},
        "uid=crito,ou=people,dc=30loops,dc=net": {
            "uid": "crito", "userPassword": "secret"}
    }
    # Compare the expected directory with the MockLDAP directory
    eq_(directory, mock_ldap.directory)

.. _Mock: http://www.voidspace.org.uk/python/mock/
