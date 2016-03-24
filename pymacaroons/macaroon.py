from __future__ import unicode_literals
import copy
from base64 import standard_b64encode

from pymacaroons.binders import HashSignaturesBinder
from pymacaroons.serializers.binary_serializer import BinarySerializer
from pymacaroons.exceptions import MacaroonInitException
from pymacaroons.utils import (
    convert_to_bytes,
    convert_to_string,
    create_initial_signature
)
from pymacaroons.caveat_delegates import (
    FirstPartyCaveatDelegate, ThirdPartyCaveatDelegate)


class Macaroon(object):

    def __init__(self,
                 location=None,
                 identifier=None,
                 key=None,
                 caveats=None,
                 signature=None):
        self.caveats = caveats or []
        self.location = location or ''
        self.identifier = identifier or ''
        self.signature = signature or ''
        self.first_party_caveat_delegate = FirstPartyCaveatDelegate()
        self.third_party_caveat_delegate = ThirdPartyCaveatDelegate()
        if key:
            self.signature = create_initial_signature(
                convert_to_bytes(key), convert_to_bytes(identifier)
            )

    @classmethod
    def deserialize(cls, serialized, serializer=None):
        serialized = convert_to_string(serialized)
        serializer = serializer or BinarySerializer()
        if serialized:
            return serializer.deserialize(serialized)
        else:
            raise MacaroonInitException(
                'Must supply serialized macaroon.'
            )

    @property
    def location(self):
        return convert_to_string(self._location)

    @location.setter
    def location(self, string_or_bytes):
        self._location = convert_to_bytes(string_or_bytes)

    @property
    def identifier(self):
        return convert_to_string(self._identifier)

    @identifier.setter
    def identifier(self, string_or_bytes):
        self._identifier = convert_to_bytes(string_or_bytes)

    @property
    def signature(self):
        return convert_to_string(self._signature)

    @signature.setter
    def signature(self, string_or_bytes):
        self._signature = convert_to_bytes(string_or_bytes)

    @property
    def signature_bytes(self):
        return self._signature

    def copy(self):
        return copy.deepcopy(self)

    def serialize(self, serializer=None):
        serializer = serializer or BinarySerializer()
        return serializer.serialize(self)

    def inspect(self):
        combined = 'location {loc}\n'.format(loc=self.location)
        combined += 'identifier {id}\n'.format(id=self.identifier)
        for caveat in self.caveats:
            combined += 'cid {cid}\n'.format(cid=caveat.caveat_id)
            if caveat.verification_key_id and caveat.location:
                vid = convert_to_string(
                    standard_b64encode(caveat.verification_key_id)
                )
                combined += 'vid {vid}\n'.format(vid=vid)
                combined += 'cl {cl}\n'.format(cl=caveat.location)
        combined += 'signature {sig}'.format(sig=self.signature)
        return combined

    def first_party_caveats(self):
        return [caveat for caveat in self.caveats if caveat.first_party()]

    def third_party_caveats(self):
        return [caveat for caveat in self.caveats if caveat.third_party()]

    def prepare_for_request(self, macaroon):
        protected = macaroon.copy()
        return HashSignaturesBinder(self).bind(protected)

    def add_first_party_caveat(self, predicate, **kwargs):
        return self.first_party_caveat_delegate.add_first_party_caveat(
            self, predicate, **kwargs
        )

    def add_third_party_caveat(self, location, key, key_id, **kwargs):
        return self.third_party_caveat_delegate.add_third_party_caveat(
            self, location, key, key_id, **kwargs
        )
