import os

from setuptools import find_packages, setup

from macaroons import __version__


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='pymacaroons',
    version=__version__,
    description='Macaroon library for Python',
    author='Evan Cordell',
    author_email='evan.cordell@localmed.com',
    url='',
    license='MIT',
    packages=find_packages(exclude=['tests', 'tests.*']),
    include_package_data=True,
    long_description=read('README.md'),
    install_requires=[
        'six>=1.7.3',
        'libnacl>=1.3.5',
        'streql>=3.0.2',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security :: Cryptography',
        'Topic :: Security'
    ],
)
