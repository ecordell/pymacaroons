import os
import sys

from setuptools import find_packages, setup


def read_file(*paths):
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, *paths)) as f:
        return f.read()

# Get long_description from index.rst:
long_description = read_file('docs', 'index.rst')
long_description = long_description.strip().split('split here', 2)[1][:-12]

setup(
    name='pymacaroons',
    version="0.12.0",
    description='Macaroon library for Python',
    author='Evan Cordell',
    author_email='cordell.evan@gmail.com',
    url='https://github.com/ecordell/pymacaroons',
    license='MIT',
    packages=find_packages(exclude=['tests', 'tests.*']),
    include_package_data=True,
    long_description=long_description,
    install_requires=[
        'six>=1.8.0',
        'libnacl>=1.3.6,<1.6',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security :: Cryptography',
        'Topic :: Security'
    ],
)
