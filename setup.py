from setuptools import setup, find_packages
import os
import sys

from version import __version__

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

extra = {}
requirements = ['python-ldap'],
tests_require = ['nose', 'Mock', 'coverage', 'unittest2', 'python-ldap']

# In case we use python3
if sys.version_info >= (3,):
    extra['use_2to3'] = True


setup(
    name = "fakeldap",
    version = __version__,
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
    url = "https://github.com/30loops/fakeldap",
    description = "An implementation of a LDAPObject to fake a ldap server in unittests.",
    long_description = read('README.rst'),
    classifiers = [
        'Development Status :: 2 - Pre-Alpha',
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
