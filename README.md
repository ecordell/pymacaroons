# PyMacaroons

This is a python implementation of the Macaroon interface.

The libmacaroons library comes with python bindings, but pymacaroons is implemented in python for further portability. Benchmarks coming, but some speed tradeoffs are expected.

Both pymacaroons and libmacaroons use the same underlying cryptographic library libsodium.

To install libsodium on mac, simply run:

    brew install libsodium
