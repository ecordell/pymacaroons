import os

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
    version="0.13.0",
    description='Macaroon library for Python',
    author='Evan Cordell',
    author_email='cordell.evan@gmail.com',
    url='https://github.com/ecordell/pymacaroons',
    license='MIT',
    packages=find_packages(exclude=['tests', 'tests.*']),
    include_package_data=True,
    package_data={package: ["py.typed", ".pyi", "**/.pyi"] for package in find_packages(exclude=['tests', 'tests.*'])},
    long_description=long_description,
    install_requires=[
        'six>=1.8.0',
        'PyNaCl>=1.1.2,<2.0',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security :: Cryptography',
        'Topic :: Security'
    ],
)
