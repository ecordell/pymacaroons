from __future__ import unicode_literals
import copy

from pymacaroons.raw_macaroon import RawMacaroon
from pymacaroons.serializers.binary_serializer import BinarySerializer
from pymacaroons.serializers.json_serializer import JsonSerializer
from pymacaroons.exceptions import MacaroonInitException
from pymacaroons.utils import convert_to_bytes, convert_to_string


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
            return BinarySerializer().deserialize(serialized)
        else:
            raise MacaroonInitException(
                'Must supply binary serialized macaroon.'
            )

    @staticmethod
    def from_json(serialized):
        if serialized:
            return JsonSerializer().deserialize(serialized)
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

    def copy(self):
        return copy.deepcopy(self)

    # Concatenates location, id, all caveats, and signature,
    # and then base64 encodes them
    def serialize(self):
        return BinarySerializer().serialize(self)

    def serialize_json(self):
        return JsonSerializer().serialize(self)

    def inspect(self):
        combined = 'location {loc}\n'.format(loc=self.location)
        combined += 'identifier {id}\n'.format(id=self.identifier)
        for caveat in self.caveats:
            combined += 'cid {cid}\n'.format(cid=caveat.caveatId)
            if caveat.verificationKeyId and caveat.location:
                combined += 'vid {vid}\n'.format(vid=caveat.verificationKeyId)
                combined += 'cl {cl}\n'.format(cl=caveat.location)
        combined += 'signature {sig}'.format(sig=self.signature)
        return combined

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
