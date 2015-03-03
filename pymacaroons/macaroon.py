from __future__ import unicode_literals
from base64 import standard_b64encode
import copy
import binascii
from libnacl.secret import SecretBox
from pymacaroons import Caveat

from pymacaroons.binders import HashSignaturesBinder
from pymacaroons.serializers.binary_serializer import BinarySerializer
from pymacaroons.exceptions import MacaroonInitException
from pymacaroons.utils import convert_to_bytes, convert_to_string, \
    create_initial_macaroon_signature, truncate_or_pad, generate_derived_key, \
    sign_third_party_caveat, sign_first_party_caveat


class Macaroon(object):

    def __init__(self,
                 location=None,
                 identifier=None,
                 key=None,
                 default_binder_class=None,
                 default_serializer=None,
                 caveats=None,
                 signature=None):
        self.caveats = caveats or []
        if location:
            self.location = location
        if identifier:
            self.identifier = identifier
        if location and identifier and key:
            self.signature = create_initial_macaroon_signature(
                convert_to_bytes(key), convert_to_bytes(identifier)
            )
        if signature:
            self.signature = signature
        self.binder_class = default_binder_class or HashSignaturesBinder
        self.serializer = default_serializer or BinarySerializer()

    @staticmethod
    def deserialize(serialized, serializer=None):
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
    def caveats(self):
        return self._caveats

    @caveats.setter
    def caveats(self, caveats):
        self._caveats = caveats

    def copy(self):
        return copy.deepcopy(self)

    def serialize(self, serializer=None):
        serializer = serializer or self.serializer
        return serializer.serialize(self)

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
    def prepare_for_request(self, macaroon, binder_class=None):
        binder_class = binder_class or self.binder_class
        protected = macaroon.copy()
        return binder_class(self).bind(protected)

    # The existing macaroon signature is the key for hashing the
    # caveat being added. This new hash becomes the signature of
    # the macaroon with caveat added.
    def add_first_party_caveat(self, predicate):
        predicate = convert_to_bytes(predicate)
        caveat = Caveat(caveatId=convert_to_bytes(predicate))
        self.caveats.append(caveat)
        encode_key = binascii.unhexlify(self._signature)
        self._signature = sign_first_party_caveat(encode_key, predicate)
        return self

    # The third party caveat key is encrypted useing the current signature, and
    # the caveat is added to the list. The existing macaroon signature
    # is the key for hashing the string (verificationId + caveatId).
    # This new hash becomes the signature of the macaroon with caveat added.
    def add_third_party_caveat(self, location, key, key_id, nonce=None):
        derived_key = truncate_or_pad(generate_derived_key(convert_to_bytes(
            key)))
        old_key = truncate_or_pad(binascii.unhexlify(self._signature))
        box = SecretBox(key=old_key)
        encrypted = box.encrypt(derived_key, nonce=nonce)
        verificationKeyId = standard_b64encode(encrypted)
        caveat = Caveat(
            caveatId=key_id,
            location=location,
            verificationKeyId=verificationKeyId
        )
        self._caveats.append(caveat)
        encode_key = binascii.unhexlify(self._signature)
        self._signature = sign_third_party_caveat(
            encode_key,
            caveat._verificationKeyId,
            caveat._caveatId
        )
        return self
