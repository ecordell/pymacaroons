# PyMacaroons

[![Build Status](https://travis-ci.org/ecordell/pymacaroons.svg?branch=master)](https://travis-ci.org/ecordell/pymacaroons) [![Coverage Status](https://coveralls.io/repos/ecordell/pymacaroons/badge.png)](https://coveralls.io/r/ecordell/pymacaroons) [![Downloads](https://img.shields.io/pypi/dd/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/) [![Latest Version](https://img.shields.io/pypi/v/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/) [![Supported Python versions](https://img.shields.io/pypi/pyversions/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/) [![Supported Python implementations](https://img.shields.io/pypi/implementation/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/) [![Development Status](https://img.shields.io/pypi/status/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/) [![Wheel Status](https://img.shields.io/pypi/wheel/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/) [![License](https://img.shields.io/pypi/l/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/)

This is a Python implementation of Macaroons. It is still under active development but is in a useable state - please report any bugs in the issue tracker.

## What is a Macaroon? 
Macaroons, like cookies, are a form of bearer credential. Unlike opaque tokens, macaroons embed *caveats* that define specific authorization requirements for the *target service*, the service that issued the root macaroon and which is capable of verifying the integrity of macaroons it recieves. 

Macaroons allow for delegation and attenuation of authorization. They are simple and fast to verify, and decouple authorization policy from the enforcement of that policy.

For a simple example, see the [Quickstart Guide](#quickstart). For more in-depth examples check out the [functional tests](https://github.com/ecordell/pymacaroons/blob/master/tests/functional_tests/functional_tests.py) and [references](#references-and-further-reading).

## Installing 

PyMacaroons requires a sodium library like libsodium or tweetnacl to be installed on the host system.

To install libsodium on mac, simply run:

    brew install libsodium

For other systems, see the [libsodium documentation](http://doc.libsodium.org/).

To install PyMacaroons:

    pip install pymacaroons


## Quickstart

### Create a Macaroon

```python
from pymacaroons import Macaroon, Verifier

# Keys for signing macaroons are associated with some identifier for later 
# verification. This could be stored in a database, key value store, 
# memory, etc.
keys = {
    'key-for-bob': 'asdfasdfas-a-very-secret-signing-key'
}

# Construct a Macaroon. The location and identifier will be visible after
# construction, and identify which service and key to use to verify it.
m = Macaroon(
    location='cool-picture-service.example.com',
    identifier='key-for-bob',
    key=keys['key-for-bob']
)

# Add a caveat for the target service
m.add_first_party_caveat('picture_id = bobs_cool_cat.jpg')

# Inspect Macaroon (useful for debugging)
print(m.inspect())
# location cool-picture-service.example.com
# identifier key-for-bob
# cid picture_id = bobs_cool_cat.jpg
# signature 83d8fa280b09938d3cffe045634f544ffaf712ff2c51ac34828ae8a42b277f8f

# Serialize for transport in a cookie, url, OAuth token, etc
serialized = m.serialize()

print(serialized)
# MDAyZWxvY2F0aW9uIGNvb2wtcGljdHVyZS1zZXJ2aWNlLmV4YW1wbGUuY29tCjAwMWJpZGVudGlmaWVyIGtleS1mb3ItYm9iCjAwMjdjaWQgcGljdHVyZV9pZCA9IGJvYnNfY29vbF9jYXQuanBnCjAwMmZzaWduYXR1cmUgg9j6KAsJk408_-BFY09UT_r3Ev8sUaw0goropCsnf48K
```

### Verifying Macaroon
```python
# Some time later, the service recieves the macaroon and must verify it
n = Macaroon.deserialize("MDAyZWxvY2F0aW9uIGNvb2wtcGljdHVyZS1zZXJ2aWNlLmV4YW1wbGUuY29tCjAwMWJpZGVudGlmaWVyIGtleS1mb3ItYm9iCjAwMjdjaWQgcGljdHVyZV9pZCA9IGJvYnNfY29vbF9jYXQuanBnCjAwMmZzaWduYXR1cmUgg9j6KAsJk408_-BFY09UT_r3Ev8sUaw0goropCsnf48K")

v = Verifier()

# General caveats are verified by arbitrary functions
# that return True only if the caveat is understood and met
def picture_access_validator(predicate):
    # in this case, predicate = 'picture_id = bobs_cool_cat.jpg'
    if predicate.split(' = ')[0] != 'picture_id':
        return False
    return predicate.split(' = ')[1] == 'bobs_cool_cat.jpg'
    
# The verifier is informed of all relevant contextual information needed
# to verify incoming macaroons
v.satisfy_general(picture_access_validator)

# Note that in this case, the picture_access_validator() is just checking
# equality. This is equivalent to a satisfy_exact call, which just checks for
# string equality
v.satisfy_exact('picture_id = bobs_cool_cat.jpg')

# Verify the macaroon using the key matching the macaroon identifier
verified = v.verify(
    n,
    keys[n.identifier]
)

# if verified is True, the macaroon was untampered (signatures matched) AND 
# all caveats were met
```

## Documentation

The latest documentation can always be found on [ReadTheDocs](http://pymacaroons.readthedocs.org/en/latest/).

## Python notes

Compatible with Python 2 and 3. CI builds are generated for 2.6, 2.7, 3.3 and 3.4, as well as PyPy and PyPy3. May be compatible with other versions (or may require tweaking - feel free to contribute!)

## Running Tests

To run the tests:

`tox`

To run against a specific version of Python:

`tox -e py34`

[tox](https://tox.readthedocs.org/en/latest/index.html) is used for running tests locally against multiple versions of Python. Tests will only run against versions available to tox. 

## More Macaroons

The [libmacaroons library](https://github.com/rescrv/libmacaroons) comes with Python and Go bindings, but PyMacaroons is implemented directly in Python for further portability and ease of installation. Benchmarks coming, but some speed tradeoffs are expected.

The [Ruby-Macaroons](https://github.com/localmed/ruby-macaroons) library is available for Ruby. PyMacaroons and Ruby-Macaroons are completely compatible (they can be used interchangibly within the same target service).

PyMacaroons, libmacaroons, and Ruby-Macaroons all use the same underlying cryptographic library (libsodium).

## References and Further Reading

- [The Macaroon Paper](http://research.google.com/pubs/pub41892.html)
- [Mozilla Macaroon Tech Talk](https://air.mozilla.org/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
- [libmacaroons](https://github.com/rescrv/libmacaroons)
- [Ruby-Macaroons](https://github.com/localmed/ruby-macaroons)
- [libnacl](https://github.com/saltstack/libnacl)

