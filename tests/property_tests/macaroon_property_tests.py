from __future__ import unicode_literals

from mock import *
from nose.tools import *
from hypothesis import assume, given, strategy
from hypothesis.specifiers import one_of, sampled_from

from six import text_type, binary_type
from pymacaroons import Macaroon, Verifier
from pymacaroons.utils import convert_to_bytes


ascii_text_strategy = strategy(
    [sampled_from(map(chr, range(0, 128)))]
).map(lambda c: ''.join(c))

ascii_bin_strategy = strategy(ascii_text_strategy).map(
    lambda s: convert_to_bytes(s)
)


class TestMacaroon(object):

    def setup(self):
        pass

    @given(
        key_id=one_of((ascii_text_strategy, ascii_bin_strategy)),
        loc=one_of((ascii_text_strategy, ascii_bin_strategy)),
        key=one_of((ascii_text_strategy, ascii_bin_strategy))
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
