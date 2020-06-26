from __future__ import unicode_literals

from hypothesis import *
from hypothesis.specifiers import *

from pymacaroons import Macaroon, MACAROON_V1, MACAROON_V2
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
            key=key,
            version=MACAROON_V1
        )
        deserialized = Macaroon.deserialize(macaroon.serialize())
        assert macaroon.identifier == deserialized.identifier
        assert macaroon.location == deserialized.location
        assert macaroon.signature == deserialized.signature
        macaroon = Macaroon(
            location=loc,
            identifier=key_id,
            key=key,
            version=MACAROON_V2
        )
        deserialized = Macaroon.deserialize(macaroon.serialize())
        assert macaroon.identifier_bytes == deserialized.identifier_bytes
        assert macaroon.location == deserialized.location
        assert macaroon.signature == deserialized.signature
