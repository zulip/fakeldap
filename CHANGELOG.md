# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [0.6.1] - 2017-11-14
## Changed
- Switch from python-ldap to pyldap. python-ldap doesn't support Python3, so
  installing fakeldap on Python3 fails due to Python3-incompatible syntax in
  python-ldap. pyldap supports Python3 and is backwards-compatible with
  python-ldap.

## [0.6] - 2017-11-10
### Changed
- Use authentic exceptions as defined in python-ldap instead of duplicate
  exceptions defined internally. When caller code substitutes the fakeldap
  for the real one in a test, it expects (and tries to catch) the authentic
  python-ldap exceptions, not the duplicate ones defined in fakeldap.
- Add version.py to store version number.
- Add support for Python3.
- Start using logging instead of prints.
