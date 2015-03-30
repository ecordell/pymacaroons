from __future__ import unicode_literals

from mock import *
from nose.tools import *
from hypothesis import *
from hypothesis.specifiers import *

from six import text_type, binary_type
from pymacaroons import Macaroon, Verifier


ascii_text_stategy = strategy(text_type).map(
    lambda s: s.encode('ascii', 'ignore')
)

ascii_bin_strategy = strategy(binary_type).map(
    lambda s: s.decode('ascii', 'ignore')
)


class TestMacaroon(object):

    def setup(self):
        pass

    @given(
        key_id=one_of((ascii_text_stategy, ascii_bin_strategy)),
        loc=one_of((ascii_text_stategy, ascii_bin_strategy)),
        key=one_of((ascii_text_stategy, ascii_bin_strategy))
    )
    def test_serializing_deserializing_macaroon(self, key_id, loc, key):
        assume(key_id and loc and key)
        macaroon = Macaroon(
            location=loc,
            identifier=key_id,
            key=key
        )
        deserialized = Macaroon.deserialize(macaroon.serialize())
        assert_equal(macaroon.identifier, deserialized.identifier)
        assert_equal(macaroon.location, deserialized.location)
        assert_equal(macaroon.signature, deserialized.signature)
