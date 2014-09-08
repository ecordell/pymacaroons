# PyMacaroons

This is a Python implementation of Macaroons. *They're better than cookies!*

## Installing 

Both pymacaroons and libmacaroons use the same underlying cryptographic library libsodium.

To install libsodium on mac, simply run:

    brew install libsodium

To install PyMacaroons:

    pip install pymacaroons


## Python notes

Compatible with Python 2 and 3. 

## Prior Art

The libmacaroons library comes with python bindings, but pymacaroons is implemented directly in Python for further portability. Benchmarks coming, but some speed tradeoffs are expected.
