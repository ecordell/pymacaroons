[![Build Status](https://travis-ci.org/ecordell/pymacaroons.svg?branch=master)](https://travis-ci.org/ecordell/pymacaroons)[![Coverage Status](https://coveralls.io/repos/ecordell/pymacaroons/badge.png)](https://coveralls.io/r/ecordell/pymacaroons)

# PyMacaroons

This is a Python implementation of Macaroons. It is still under active development but is in a useable state - please report any bugs in the issue tracker.

## What is a Macaroon? 
Macaroons, like cookies, are a form of bearer credential. Unlike opaque tokens, macaroons embed *caveats* that define specific authorization requirements for the *target service*, the service that issued the root macaroon and which is capable of verifying the integrity of macaroons it recieves. 

Macaroons allow for delegation and attenuation of authorization. They are simple and fast to verify, and decouple authorization policy from the enforcement of that policy.

For a simple example, see the [Quickstart](#quickstart). For more in-depth examples look at the functional tests and check out the references.

## Installing 

PyMacaroons requires a sodium library like libsodium or tweetnacl to be installed on the host system.

To install libsodium on mac, simply run:

    brew install libsodium

For other systems, see the [libsodium documentation](http://doc.libsodium.org/).

To install PyMacaroons:

    pip install pymacaroons


## Quickstart

    from macaroons.macaroon import Macaroon
    from macaroons.verifier import Verifier

    keys = {
        'secret_key_1': 'a very secret key, used to sign the macaroon'
    }
    # Construct a Macaroon. The location and identifier will be visible after
    # construction, and identify which service and key to use to verify it.
    m = Macaroon(
        location='http://mybank/',
        identifier='secret_key_1',
        key=keys['secret_key_1']
    )

    # Add a caveat for the target service
    m.add_first_party_caveat('general caveat')


    # General caveats are verified by an arbitrary functions
    def general_caveat_validator(predicate):
        return predicate == 'general caveat'

    # Some time later, the service recieves the macaroon and must verify it
    v = Verifier()

    # The verifier is informed of all relevant contextual information needed
    # to verify incoming macaroons
    v.satisfy_general(general_caveat_validator)

    # Note that in this case, the general_caveat_validator() is just checking
    # equality. This is equivalent to:
    v.satisfy_exact('general caveat')

    # Verify the macaroon using the key matching the macaroon identifier
    verified = v.verify(
        m,
        keys[m.identifier]
    )


## Documentation

The latest documentation can always be found on [ReadTheDocs](http://pymacaroons.readthedocs.org/en/latest/).

## Python notes

Compatible with Python 2 and 3. CI builds are generated for 2.6, 2.7, 3.3 and 3.4. May be compatible with other versions (or may require tweaking - feel free to contribute!)

## More Macaroons

The [libmacaroons library](https://github.com/rescrv/libmacaroons) comes with Python and Go bindings, but PyMacaroons is implemented directly in Python for further portability and ease of installation. Benchmarks coming, but some speed tradeoffs are expected.

Both PyMacaroons and libmacaroons use the same underlying cryptographic library (libsodium).

## References and Further Reading

[The Macaroon Paper](http://research.google.com/pubs/pub41892.html)
[Mozilla Macaroon Tech Talk](https://air.mozilla.org/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
[libmacaroons](https://github.com/rescrv/libmacaroons)

