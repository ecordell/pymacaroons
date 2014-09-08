# PyMacaroons

This is a Python implementation of the Macaroon concept. *They're better than cookies!*

## Installing 

Both pymacaroons and libmacaroons use the same underlying cryptographic library libsodium.

To install libsodium on mac, simply run:

    brew install libsodium

To install PyMacaroons:

    pip install pymacaroons


## Python notes

Must be run on Python 3 or Python >= 2.7.7. Lower versions do not have the `hmac.compare_digest` method that prevents timing attacks.

Alternately, a different library could be used to create and compare hmacs.

## Prior Art

The libmacaroons library comes with python bindings, but pymacaroons is implemented directly in Python for further portability. Benchmarks coming, but some speed tradeoffs are expected.
