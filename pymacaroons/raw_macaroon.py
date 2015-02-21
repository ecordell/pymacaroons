from __future__ import unicode_literals

import binascii
import copy
from base64 import standard_b64encode

from libnacl.secret import SecretBox

from pymacaroons.caveat import Caveat
from pymacaroons.binders import HashSignaturesBinder
from pymacaroons.utils import (truncate_or_pad,
                               create_initial_macaroon_signature,
                               generate_derived_key,
                               sign_first_party_caveat,
                               sign_third_party_caveat)


class RawMacaroon(object):
    """
    RawMacaroon uses byte types internally and in its public interface.

    This relegates all string/byte conversion and input validation to
    the to Macaroon proxy class, which is the public interface.

    RawMacaroons should not be constructed directly.

    """

    def __init__(self,
                 location=None,
                 identifier=None,
                 key=None,
                 caveats=None,
                 signature=None):
        self._caveats = []
        if location:
            self._location = location
        if identifier:
            self._identifier = identifier
        if location and identifier and key:
            self._signature = create_initial_macaroon_signature(
                key, identifier
            )
        if signature:
            self._signature = signature

    @property
    def location(self):
        return self._location

    @property
    def identifier(self):
        return self._identifier

    @property
    def signature(self):
        return self._signature

    @property
    def caveats(self):
        return self._caveats

    def copy(self):
        return copy.deepcopy(self)

    def first_party_caveats(self):
        return [caveat for caveat in self.caveats if caveat.first_party()]

    def third_party_caveats(self):
        return [caveat for caveat in self.caveats if caveat.third_party()]

    # Protects discharge macaroons in the event they are sent to
    # the wrong location by binding to the root macaroon
    def prepare_for_request(self, macaroon):
        return HashSignaturesBinder(self).bind(macaroon)

    # The existing macaroon signature is the key for hashing the
    # caveat being added. This new hash becomes the signature of
    # the macaroon with caveat added.
    def add_first_party_caveat(self, predicate):
        caveat = Caveat(caveatId=predicate)
        self._caveats.append(caveat)
        encode_key = binascii.unhexlify(self.signature)
        self._signature = sign_first_party_caveat(encode_key, predicate)
        return self

    # The third party caveat key is encrypted useing the current signature, and
    # the caveat is added to the list. The existing macaroon signature
    # is the key for hashing the string (verificationId + caveatId).
    # This new hash becomes the signature of the macaroon with caveat added.
    def add_third_party_caveat(self, location, key, key_id, nonce=None):
        derived_key = truncate_or_pad(generate_derived_key(key))
        old_key = truncate_or_pad(binascii.unhexlify(self.signature))
        box = SecretBox(key=old_key)
        encrypted = box.encrypt(derived_key, nonce=nonce)
        verificationKeyId = standard_b64encode(encrypted)
        caveat = Caveat(
            caveatId=key_id,
            location=location,
            verificationKeyId=verificationKeyId
        )
        self._caveats.append(caveat)
        encode_key = binascii.unhexlify(self.signature)
        self._signature = sign_third_party_caveat(
            encode_key,
            caveat._verificationKeyId,
            caveat._caveatId
        )
        return self
