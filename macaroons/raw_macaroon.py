from __future__ import unicode_literals

import binascii
import struct
import json

from base64 import standard_b64encode, urlsafe_b64decode, urlsafe_b64encode

from libnacl.secret import SecretBox

from macaroons.caveat import Caveat
from macaroons.utils import (truncate_or_pad,
                             convert_to_bytes,
                             convert_to_string,
                             generate_derived_key,
                             hmac_digest,
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
                 serialized=None,
                 signature=None,
                 json=None):
        self._serialized = None
        self._caveats = []
        if location and identifier and key:
            self._location = location
            self._identifier = identifier
            self._signature = self._create_initial_macaroon_signature(key)
            self._serialized = None
        elif location and identifier and signature:
            # This is only used from the verifier when we need to skip
            # the inital signature hashing for verifying
            # third party caveats
            self._location = location
            self._identifier = identifier
            self._signature = signature
            self._serialized = None
        elif serialized:
            self._serialized = serialized
            self._deserialize(serialized)
        elif json:
            self._deserialize_json(json)
        else:
            pass

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

    # TODO
    def validate(self):
        pass

    def copy(self):
        return RawMacaroon(serialized=self.serialize())

    # Concatenates location, id, all caveats, and signature,
    # and then base64 encodes them
    def serialize(self):
        combined = self._packetize(b'location', self.location)
        combined += self._packetize(b'identifier', self.identifier)

        for caveat in self.caveats:
            combined += self._packetize(b'cid', caveat._caveatId)

            if caveat._verificationKeyId and caveat._location:
                combined += self._packetize(b'vid', caveat._verificationKeyId)
                combined += self._packetize(b'cl', caveat._location)

        combined += self._packetize(
            b'signature',
            binascii.unhexlify(self._signature)
        )
        return urlsafe_b64encode(combined)

    def serialize_json(self):
        serialized = {
            'location': convert_to_string(self.location),
            'identifier': convert_to_string(self.identifier),
            'caveats': [caveat.to_dict() for caveat in self.caveats],
            'signature': convert_to_string(self.signature)
        }
        return json.dumps(serialized)

    def _deserialize(self, data):
        PACKET_PREFIX_LENGTH = 4
        decoded = urlsafe_b64decode(data)

        index = 0

        while index < len(decoded):
            packet_length = int(
                struct.unpack(
                    b"4s",
                    decoded[index:index + PACKET_PREFIX_LENGTH]
                )[0],
                16
            )
            packet = decoded[index:index + packet_length]

            start_index = index + PACKET_PREFIX_LENGTH
            end_index = index + packet_length - 1
            if packet[PACKET_PREFIX_LENGTH:].startswith(b'location'):
                self._location = \
                    decoded[start_index + len(b'location '): end_index]
                index = index + packet_length

            if packet[PACKET_PREFIX_LENGTH:].startswith(b'identifier'):
                self._identifier = \
                    decoded[start_index + len(b'identifier '): end_index]
                index = index + packet_length

            if packet[PACKET_PREFIX_LENGTH:].startswith(b'cid'):
                cid = decoded[start_index + len(b'cid '): end_index]
                self.caveats.append(Caveat(caveatId=cid))
                index = index + packet_length

            if packet[PACKET_PREFIX_LENGTH:].startswith(b'vid'):
                vid = decoded[start_index + len(b'vid '): end_index]
                self.caveats[-1].verificationKeyId = vid
                index = index + packet_length

            if packet[PACKET_PREFIX_LENGTH:].startswith(b'cl'):
                cl = decoded[start_index + len(b'cl '): end_index]
                self.caveats[-1].location = cl
                index = index + packet_length

            if packet[PACKET_PREFIX_LENGTH:].startswith(b'signature'):
                self._signature = binascii.hexlify(
                    decoded[start_index + len(b'signature '): end_index]
                )
                index = len(decoded)

        return self

    def _deserialize_json(self, data):
        deserialized = json.loads(convert_to_string(data))
        self._location = deserialized['location']
        self._identifier = deserialized['identifier']
        for c in deserialized['caveats']:
            caveat = Caveat(
                caveatId=c['cid'],
                verificationKeyId=c['vid'],
                location=c['cl']
            )
            self._caveats.append(caveat)
        self._signature = convert_to_bytes(deserialized['signature'])
        return self

    def inspect(self):
        combined = 'location' + ' ' + self.location + '\n'
        combined += 'identifier' + ' ' + self.identifier + '\n'

        for caveat in self.caveats:
            combined += 'cid' + ' ' + caveat.caveatId + '\n'

            if caveat.verificationKeyId and caveat.location:
                combined += 'vid' + ' ' + \
                    caveat._verificationKeyId.decode('ascii') + '\n'
                combined += 'cl' + ' ' + caveat.location + '\n'

        combined += 'signature' + ' ' + self._signature.decode('ascii')
        return combined

    # TODO
    def is_same(self, macaroon):
        pass

    def first_party_caveats(self):
        return [caveat for caveat in self.caveats if caveat.first_party()]

    def third_party_caveats(self):
        return [caveat for caveat in self.caveats if caveat.third_party()]

    # Protects discharge macaroons in the event they are sent to
    # the wrong location by binding to the root macaroon
    def prepare_for_request(self, macaroon):
        protected = macaroon.copy()
        protected._signature = self._bind_signature(macaroon.signature)
        return protected

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
    def add_third_party_caveat(self, location, key, key_id):
        derived_key = truncate_or_pad(generate_derived_key(key))
        self._add_third_party_caveat_direct(
            location,
            derived_key,
            key_id,
            nonce=None
        )
        return self

    def _add_third_party_caveat_direct(self,
                                       location,
                                       key,
                                       key_id,
                                       nonce=None):
        old_key = truncate_or_pad(binascii.unhexlify(self.signature))
        box = SecretBox(key=old_key)
        encrypted = box.encrypt(key, nonce=nonce)
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

    def _bind_signature(self, signature):
        bound = self._macaroon_hmac_concat(
            truncate_or_pad(b'0'),
            self.signature,
            signature
        )
        return bound

    # Hashes two strings, then concatenates them and hashes the combined
    # string
    def _macaroon_hmac_concat(self, key, data1, data2):
        hash1 = hmac_digest(key, binascii.unhexlify(data1))
        hash2 = hmac_digest(key, binascii.unhexlify(data2))
        combined = hash1 + hash2
        return self._macaroon_hmac(
            key, combined
        )

    # Given a high-entropy root key _key and an identifier id, this returns
    # a valid signature sig = MAC(k, id).
    def _create_initial_macaroon_signature(self, key):
        derived_key = generate_derived_key(key)
        return self._macaroon_hmac(derived_key, self._identifier)

    def _macaroon_hmac(self, key, data):
        dig = hmac_digest(key, data)
        return binascii.hexlify(dig)

    def _packetize(self, key, data):
        PACKET_PREFIX_LENGTH = 4
        # The 2 covers the space and the newline
        packet_size = PACKET_PREFIX_LENGTH + 2 + len(key) + len(data)
        # Ignore the first two chars, 0x
        packet_size_hex = hex(packet_size)[2:]
        header = packet_size_hex.zfill(4).encode('ascii')
        packet_content = key + b' ' + data + b'\n'
        packet = struct.pack(
            convert_to_bytes("4s%ds" % len(packet_content)),
            header,
            packet_content
        )
        return packet
