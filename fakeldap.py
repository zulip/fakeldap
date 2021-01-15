# coding: utf-8

# Copyright (c) 2009, Peter Sagerson
# Copyright (c) 2011, Christo Buschek <crito@30loops.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# - Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import re
import sys
import logging
from collections import defaultdict
import ldap
from ldap.controls import SimplePagedResultsControl
import json


logger = logging.getLogger(__name__)


class BytesDump(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):                   # deal with bytes
            return obj.decode()
        return json.JSONEncoder.default(self, obj)   # everything else


class MockLDAP(object):
    """
    This is a stand-in for the python-ldap module; it serves as both the ldap
    module and the LDAPObject class. While it's temping to add some real LDAP
    capabilities here, this is designed to remain as simple as possible, so as
    to minimize the risk of creating bogus unit tests through a buggy test
    harness.

    Simple operations can be simulated, but for nontrivial searches, the client
    will have to seed the mock object with return values for expected API calls.
    This may sound like cheating, but it's really no more so than a simulated
    LDAP server. The fact is we can not require python-ldap to be installed in
    order to run the unit tests, so all we can do is verify that LDAPBackend is
    calling the APIs that we expect.

    set_return_value takes the name of an API, a tuple of arguments, and a
    return value. Every time an API is called, it looks for a predetermined
    return value based on the arguments received. If it finds one, then it
    returns it, or raises it if it's an Exception. If it doesn't find one, then
    it tries to satisfy the request internally. If it can't, it raises a
    PresetReturnRequiredError.

    At any time, the client may call ldap_methods_called_with_arguments() or
    ldap_methods_called() to get a record of all of the LDAP API calls that have
    been made, with or without arguments.
    """

    class PresetReturnRequiredError(Exception):
        pass

    SCOPE_BASE = 0
    SCOPE_ONELEVEL = 1
    SCOPE_SUBTREE = 2

    MOD_ADD = 0
    MOD_DELETE = 1
    MOD_REPLACE = 2

    #
    # Submodules
    #
    class dn(object):
        def escape_dn_chars(s):
            return s
        escape_dn_chars = staticmethod(escape_dn_chars)

    class filter(object):
        def escape_filter_chars(s):
            return s
        escape_filter_chars = staticmethod(escape_filter_chars)

    def __init__(self, directory=None):
        """
        directory is a complex structure with the entire contents of the
        mock LDAP directory. directory must be a dictionary mapping
        distinguished names to dictionaries of attributes. Each attribute
        dictionary maps attribute names to lists of values. e.g.:

        {
            "uid=alice,ou=users,dc=example,dc=com":
            {
                "uid": ["alice"],
                "userPassword": ["secret"],
            },
        }
        """
        if directory:
            self.directory = directory
        else:
            self.directory = defaultdict(lambda: {})

        self.cookie = 0
        self._async_results = {}

        self.reset()

    def reset(self):
        """
        Resets our recorded API calls and queued return values as well as
        miscellaneous configuration options.
        """
        self.calls = []
        self.return_value_maps = defaultdict(lambda: {})
        self.options = {}
        self.tls_enabled = False

    def set_return_value(self, api_name, arguments, value):
        """
        Stores a preset return value for a given API with a given set of
        arguments.
        """
        logger.info("Set value. api_name: %s, arguments: %s, value: %s" % (api_name, arguments, value))
        args_str = json.dumps(arguments, cls=BytesDump)
        self.return_value_maps[api_name][args_str] = value

    def ldap_methods_called_with_arguments(self):
        """
        Returns a list of 2-tuples, one for each API call made since the last
        reset. Each tuple contains the name of the API and a dictionary of
        arguments. Argument defaults are included.
        """
        return self.calls

    def ldap_methods_called(self):
        """
        Returns the list of API names called.
        """
        return [call[0] for call in self.calls]

    #
    # Begin LDAP methods
    #

    def set_option(self, option, invalue):
        self._record_call('set_option', {
            'option': option,
            'invalue': invalue
        })

        self.options[option] = invalue

    def initialize(self, uri, trace_level=0, trace_file=sys.stdout, trace_stack_limit=None):
        self._record_call('initialize', {
            'uri': uri,
            'trace_level': trace_level,
            'trace_file': trace_file,
            'trace_stack_limit': trace_stack_limit
        })

        value = self._get_return_value(
            'initialize',
            (uri, trace_level, trace_file, trace_stack_limit)
        )
        if value is None:
            value = self

        return value

    def simple_bind_s(self, who='', cred=''):
        self._record_call('simple_bind_s', {
            'who': who,
            'cred': cred
        })

        value = self._get_return_value('simple_bind_s', (who, cred))
        if value is None:
            value = self._simple_bind_s(who, cred)

        return value

    def search_ext(
        self,
        base,
        scope,
        filterstr='(objectClass=*)',
        attrlist=None,
        attrsonly=0,
        serverctrls=None,
        clientctrls=None,
        timeout=-1,
        sizelimit=0
    ):
        self._record_call('search_ext', {
            'base': base,
            'scope': scope,
            'filterstr': filterstr,
            'attrlist': attrlist,
            'attrsonly': attrsonly,
            'serverctrls': serverctrls,
            'clientctrls': clientctrls,
            'timeout': timeout,
            'sizelimit': sizelimit
        })
        msgid = self.cookie
        serverctrls[0].cookie = b'%d' % msgid

        self._async_results[self.cookie] = {}
        self._async_results[self.cookie]['ctrls'] = serverctrls
        value = self._get_return_value('search_ext', (base, scope, filterstr, attrlist, attrsonly))
        if value is None:
            value = self._search_s(base, scope, filterstr, attrlist, attrsonly)
        self._async_results[self.cookie]['data'] = value
        self.cookie += 1
        return msgid

    def result3(self, msgid=ldap.RES_ANY, all=1, timeout=None):
        self._record_call('result3', {
            'msgid': msgid,
            'all': all,
            'timeout': timeout,
        })

        if self._async_results:
            if msgid == ldap.RES_ANY:
                msgid = self._async_results.keys()[0]
        if msgid in self._async_results:
            data = self._async_results[msgid]['data']
            controls = self._async_results[msgid]['ctrls']
            del self._async_results[msgid]
        else:
            data = []
        controls[0].cookie = None

        return ldap.RES_SEARCH_RESULT, data, msgid, controls

    def search_s(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        self._record_call('search_s', {
            'base': base,
            'scope': scope,
            'filterstr': filterstr,
            'attrlist': attrlist,
            'attrsonly': attrsonly
        })
        value = self._get_return_value(
            'search_s',
            (base, scope, filterstr, attrlist, attrsonly)
        )
        if value is None:
            value = self._search_s(base, scope, filterstr, attrlist, attrsonly)

        return value

    def start_tls_s(self):
        self.tls_enabled = True

    def compare_s(self, dn, attr, value):
        self._record_call('compare_s', {
            'dn': dn,
            'attr': attr,
            'value': value
        })

        result = self._get_return_value('compare_s', (dn, attr, value))
        if result is None:
            result = self._compare_s(dn, attr, value)

        return result

    def modify_s(self, dn, mod_attrs):
        self._record_call('modify_s', {
            'dn': dn,
            'mod_attrs': mod_attrs
        })

        mod_attrs = tuple(mod_attrs)
        result = self._get_return_value('modify_s', (dn, mod_attrs))
        if result is None:
            result = self._modify_s(dn, mod_attrs)

        return result

    def delete_s(self, dn):
        self._record_call('delete_s', {
            'dn': dn
        })

        result = self._get_return_value('delete_s', dn)
        if result is None:
            result = self._delete_s(dn)

        return result

    def add_s(self, dn, record):
        self._record_call('add_s', {
            'dn': dn,
            'record': record,
        })

        record = self._mangle_record(record)

        result = self._get_return_value('add_s', (dn, record))
        if result is None:
            result = self._add_s(dn, record)

        return result

    def rename_s(self, dn, newrdn, superior=None):
        self._record_call('rename_s', {
            'dn': dn,
            'newrdn': newrdn,
            'superior': superior,
        })

        result = self._get_return_value('rename_s', (dn, newrdn, superior))
        if result is None:
            result = self._rename_s(dn, newrdn, superior)

        return result

    def unbind_s(self):
        self._record_call('unbind_s', {})

    #
    # Internal implementations
    #

    def _simple_bind_s(self, who='', cred=''):
        success = False

        if(who == '' and cred == ''):
            success = True
        elif self._compare_s(who.lower(), 'userPassword', cred):
            success = True

        if success:
            return (97, [])  # python-ldap returns this; I don't know what it means
        else:
            raise ldap.INVALID_CREDENTIALS('%s:%s' % (who, cred))

    def _compare_s(self, dn, attr, value):
        try:
            found = (value in self.directory[dn][attr])
        except KeyError:
            found = False

        return found and 1 or 0

    def _modify_s(self, dn, mod_attrs):
        try:
            entry = self.directory[dn]
        except KeyError:
            raise ldap.NO_SUCH_OBJECT

        for item in mod_attrs:
            op, key, value = item
            if op == 0:
                # FIXME: Can't handle multiple entries with the same name
                # its broken right now
                # do a MOD_ADD, assume it to be a list of values
                key.append(value)
            elif op == 1:
                # do a MOD_DELETE
                row = entry[key]
                if isinstance(row, list):
                    for i in range(len(row)):
                        if value is row[i]:
                            del row[i]
                else:
                    del entry[key]
                self.directory[dn] = entry
            elif op == 2:
                # do a MOD_REPLACE
                entry[key] = value

        self.directory[dn] = entry

        return (103, [])

    def _rename_s(self, dn, newrdn, superior=None):
        try:
            entry = self.directory[dn]
        except KeyError:
            raise ldap.NO_SUCH_OBJECT

        if not superior:
            basedn = ','.join(dn.split(',')[1:])
        else:
            basedn = superior
        newdn = newrdn + ',' + basedn
        attr, value = newrdn.split('=')

        entry[attr] = value
        self.directory[newdn] = entry
        del self.directory[dn]

        return (109, [])

    def _delete_s(self, dn):
        try:
            del self.directory[dn]
        except KeyError:
            raise ldap.NO_SUCH_OBJECT

        return (107, [])

    def _search_s(self, base, scope, filterstr, attrlist, attrsonly):
        """
        We can do a SCOPE_BASE search with the default filter and simple SCOPE_ONELEVEL
        with query of the form (attribute_name=some_value). Beyond that,
        you're on your own.
        """
        #FIXME: Implement different scopes

        if scope == self.SCOPE_BASE:
            if filterstr != '(objectClass=*)':
                raise self.PresetReturnRequiredError(
                    'search_s("%s", %d, "%s", "%s", %d)' % (base, scope, filterstr, attrlist, attrsonly)
                )
            attrs = self.directory.get(base)
            logger.debug("attrs: %s".format(attrs))
            if attrs is None:
                raise ldap.NO_SUCH_OBJECT

            return [(base, attrs)]
        elif scope == self.SCOPE_ONELEVEL:
            simple_query_regex = r"\(\w+=.+\)$"  # matches things like (some_attribute=value)
            r = re.compile(simple_query_regex)
            if r.match(filterstr) is None:  # only this very simple search is supported
                raise self.PresetReturnRequiredError(
                    'search_s("%s", %d, "%s", "%s", %d)' % (base, scope, filterstr, attrlist, attrsonly)
                )

            return self._simple_onelevel_search(base, filterstr)
        else:
            results = self.directory.get(f'search:{filterstr}', [])
            logger.debug("results: %s".format(results))
            return results

    def _add_s(self, dn, record):
        # change the record into the proper format for the internal directory
        entry = {}
        for item in record:
            entry[item[0]] = item[1]
        logger.debug("entry: %s".format(entry))
        try:
            self.directory[dn]
            raise ldap.ALREADY_EXISTS
        except KeyError:
            self.directory[dn] = entry
            return (105, [], len(self.calls), [])

    def _simple_onelevel_search(self, base, filterstr):
        search_attr_name, search_attr_value = filterstr[1:-1].split('=')

        result = []
        for dn, attrs in self.directory.items():
            if dn.endswith(',{}'.format(base)):
                if ',' in dn.strip(',{}'.format(base)):
                    # This would mean going more than one level in.
                    continue

                search_attr = attrs.get(search_attr_name)
                if search_attr == search_attr_value:
                    result.append((dn, attrs))
                elif isinstance(search_attr, list):  # if attr is in the format "attr_name": ["value", ]
                    if len(search_attr) == 1 and search_attr[0] == search_attr_value:
                        result.append((dn, attrs))

        return result

    #
    # Utils
    #

    def _mangle_record(self, record):
        """Change lists into tuples, so that they can be hashed."""
        new_record = []

        for item in record:
            key, value = item
            if isinstance(value, list):
                value = tuple(value)
            new_record.append((key, value))

        if isinstance(new_record, list):
            new_record = tuple(new_record)

        return new_record

    def _record_call(self, api_name, arguments):
        logger.info("CALL: api: %s, arguments: %s" % (api_name, arguments))
        self.calls.append((api_name, arguments))

    def _get_return_value(self, api_name, arguments):
        args_str = json.dumps(arguments, cls=BytesDump)
        try:
            logger.info("RETURN: api: %s, arguments: %s" % (api_name, arguments))
            value = self.return_value_maps[api_name][args_str]
        except KeyError:
            value = None

        if isinstance(value, Exception):
            raise value

        return value
