from setuptools import setup, find_packages
import os
import sys

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

extra = {}
requirements = ['python-ldap'],
tests_require = ['nose', 'Mock', 'coverage', 'unittest2', 'python-ldap']

setup(
    name = "fakeldap",
    version = "0.6.4",
    #packages = find_packages('fakeldap'),
    #include_package_data=True,
    py_modules = ['fakeldap'],
    install_requires = requirements,

    tests_require=tests_require,
    setup_requires='nose',
    test_suite = "nose.collector",
    extras_require={'test': tests_require},

    author = "Christo Buschek",
    author_email = "crito@30loops.net",
    url = "https://github.com/zulip/fakeldap",
    description = "An implementation of a LDAPObject to fake a ldap server in unittests.",
    long_description = read('README.rst'),
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Testing',
    ],
    **extra
)
