from __future__ import unicode_literals

from macaroons.raw_macaroon import RawMacaroon
from macaroons.exceptions import MacaroonInitException
from macaroons.utils import convert_to_bytes, convert_to_string


class Macaroon(object):

    def __init__(self,
                 location=None,
                 identifier=None,
                 key=None):

        if location and identifier and key:
            self._raw_macaroon = RawMacaroon(
                location=convert_to_bytes(location),
                identifier=convert_to_bytes(identifier),
                key=convert_to_bytes(key)
            )
        else:
            raise MacaroonInitException(
                'Must supply all: (location, id, key).'
            )

    @staticmethod
    def from_binary(serialized):
        if serialized:
            m = Macaroon(location='x', identifier='x', key='x')
            m._raw_macaroon = RawMacaroon(
                serialized=convert_to_bytes(serialized)
            )
            return m
        else:
            raise MacaroonInitException(
                'Must supply binary serialized macaroon.'
            )

    @staticmethod
    def from_json(serialized):
        if serialized:
            m = Macaroon(location='x', identifier='x', key='x')
            m._raw_macaroon = RawMacaroon(
                json=convert_to_string(serialized)
            )
            return m
        else:
            raise MacaroonInitException(
                'Must supply json serialized macaroon.'
            )

    @property
    def location(self):
        return convert_to_string(self._raw_macaroon.location)

    @property
    def identifier(self):
        return convert_to_string(self._raw_macaroon.identifier)

    @property
    def signature(self):
        return convert_to_string(self._raw_macaroon.signature)

    @property
    def caveats(self):
        return self._raw_macaroon.caveats

    def validate(self):
        return self._raw_macaroon.validate()

    def copy(self):
        return Macaroon.from_binary(self.serialize())

    # Concatenates location, id, all caveats, and signature,
    # and then base64 encodes them
    def serialize(self):
        return self._raw_macaroon.serialize().decode('ascii')

    def serialize_json(self):
        return self._raw_macaroon.serialize_json()

    def inspect(self):
        return self._raw_macaroon.inspect()

    def is_same(self, macaroon):
        return self._raw_macaroon.is_same(macaroon._raw_macaroon)

    def first_party_caveats(self):
        return [caveat for caveat in self.caveats if caveat.first_party()]

    def third_party_caveats(self):
        return [caveat for caveat in self.caveats if caveat.third_party()]

    # Protects discharge macaroons in the event they are sent to
    # the wrong location by binding to the root macaroon
    def prepare_for_request(self, macaroon):
        protected = self.copy()
        protected._raw_macaroon = self._raw_macaroon.prepare_for_request(
            macaroon._raw_macaroon
        )
        return protected

    # The existing macaroon signature is the key for hashing the
    # caveat being added. This new hash becomes the signature of
    # the macaroon with caveat added.
    def add_first_party_caveat(self, predicate):
        self._raw_macaroon.add_first_party_caveat(
            convert_to_bytes(predicate)
        )
        return self

    # The third party caveat key is encrypted useing the current signature, and
    # the caveat is added to the list. The existing macaroon signature
    # is the key for hashing the string (verificationId + caveatId).
    # This new hash becomes the signature of the macaroon with caveat added.
    def add_third_party_caveat(self, location, key, key_id):
        return self._raw_macaroon.add_third_party_caveat(
            convert_to_bytes(location),
            convert_to_bytes(key),
            convert_to_bytes(key_id)
        )
