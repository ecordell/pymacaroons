from __future__ import unicode_literals

import hmac
import hashlib
import binascii
import base64
import six
from libnacl.secret import SecretBox

from .caveat import Caveat


class Macaroon:

    # TODO
    def __init__(self,
                 location=None,
                 identifier=None,
                 key=None,
                 serialized=None,
                 signature=None,
                 provider=None):
        self._serialized = serialized
        self._caveats = []
        # TODO: validations, only (loc, id, key) or serialized
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
        else:
            # TODO
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
        return Macaroon(serialized=self.serialize())

    # Concatenates location, id, all caveats, and signature,
    # and then base64 encodes them
    def serialize(self):
        combined = self._packetize('location', self.location.encode('ascii'))
        combined += self._packetize('identifier', self.identifier.encode('ascii'))

        # TODO: list comprehension
        for caveat in self.caveats:
            combined += self._packetize('cid', caveat.caveatId.encode('ascii'))

            if caveat.verificationKeyId and caveat.location:
                combined += self._packetize('vid', binascii.unhexlify(caveat.verificationKeyId))
                combined += self._packetize('cl', caveat.location.encode('ascii'))

        combined += self._packetize(
            'signature',
            binascii.unhexlify(self.signature)
        )
        return base64.urlsafe_b64encode(combined).decode('ascii')

    def serialize_json(self):
        pass

    # TODO: use python struct unpacking
    def _deserialize(self, data):
        PACKET_PREFIX_LENGTH = 4
        decoded = base64.urlsafe_b64decode(data.encode('ascii'))
        lines = decoded.split(b'\n')
        # location
        self._location = lines[0][PACKET_PREFIX_LENGTH + len('location '):].decode('ascii')
        # identifier
        self._identifier = lines[1][PACKET_PREFIX_LENGTH + len('identifier '):].decode('ascii')
        # caveats
        i = 2
        while i < len(lines) - 2:
            first_party = (
                lines[i][PACKET_PREFIX_LENGTH:PACKET_PREFIX_LENGTH + len('cid')] == b'cid' and
                lines[i+1][PACKET_PREFIX_LENGTH:PACKET_PREFIX_LENGTH + len('vid')] != b'vid'
            )
            if first_party:
                cid = lines[i][PACKET_PREFIX_LENGTH+len('cid '):]
                self.caveats.append(Caveat(caveatId=cid.decode('ascii')))
                i += 1  # skip vid and cl lines - already processed
            else:
                cid = lines[i][PACKET_PREFIX_LENGTH+len('cid '):]
                vid = binascii.hexlify(
                    lines[i+1][PACKET_PREFIX_LENGTH+len('vid '):]
                )
                cl = lines[i+2][PACKET_PREFIX_LENGTH+len('cl '):]
                self.caveats.append(Caveat(caveatId=cid.decode('ascii'), verificationKeyId=vid, location=cl.decode('ascii')))
                i += 3  # skip vid and cl lines - already processed

        # signature
        self._signature = \
            binascii.hexlify(
                lines[len(lines) - 2][PACKET_PREFIX_LENGTH+len('signature '):]
            )
        return self

    def inspect(self):
        combined = 'location' + ' ' + self.location + '\n'
        combined += 'identifier' + ' ' + self.identifier + '\n'

        # TODO: list comprehension
        for caveat in self.caveats:
            combined += 'cid' + ' ' + caveat.caveatId + '\n'

            if caveat.verificationKeyId and caveat.location:
                combined += 'vid' + ' ' + caveat.verificationKeyId.decode('ascii') + '\n'
                combined += 'cl' + ' ' + caveat.location + '\n'

        combined += 'signature' + ' ' + self.signature.decode('ascii')
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
        protected._signature = self._macaroon_hmac_concat(
            b'\0',
            self.signature.decode('ascii'),
            macaroon.signature.decode('ascii')
        )
        return protected

    # The existing macaroon signature is the key for hashing the
    # caveat being added. This new hash becomes the signature of
    # the macaroon with caveat added.
    def add_first_party_caveat(self, predicate):
        caveat = Caveat(caveatId=predicate)
        self._caveats.append(caveat)
        encode_key = binascii.unhexlify(self.signature)
        self._signature = self._macaroon_hmac(encode_key, predicate)
        return self

    # The third party caveat key is encrypted useing the current signature, and
    # the caveat is added to the list. The existing macaroon signature
    # is the key for hashing the string (verificationId + caveatId).
    # This new hash becomes the signature of the macaroon with caveat added.
    def add_third_party_caveat(self, location, key, key_id):
        derived_key = self._truncate_or_pad(self._generate_derived_key(key))
        self._add_third_party_caveat_direct(location, derived_key, key_id, nonce=None)
        return self

    def _add_third_party_caveat_direct(self, location, key, key_id, nonce=None):
        old_key = self._truncate_or_pad(self.signature)
        box = SecretBox(key=old_key)
        encrypted = box.encrypt(key, nonce=nonce)
        verificationKeyId = base64.standard_b64encode(encrypted)
        caveat = Caveat(
            caveatId=key_id,
            location=location,
            verificationKeyId=verificationKeyId
        )
        self._caveats.append(caveat)
        encode_key = binascii.unhexlify(self.signature)
        self._signature = self._macaroon_hmac_concat(
            encode_key,
            caveat.verificationKeyId.decode('ascii'),
            caveat.caveatId
        )
        return self

    # Hashes two strings, then concatenates them and hashes the combined
    # string
    def _macaroon_hmac_concat(self, key, data1, data2):
        hash1 = hmac.new(
            key,
            msg=data1.encode('ascii'),
            digestmod=hashlib.sha256
        ).digest()
        hash2 = hmac.new(
            key,
            msg=data2.encode('ascii'),
            digestmod=hashlib.sha256
        ).digest()
        combined = hash1 + hash2
        return hmac.new(
            key,
            msg=combined,
            digestmod=hashlib.sha256
        ).hexdigest().encode('ascii')

    # Given a high-entropy root key _key and an identifier id, this returns
    # a valid signature sig = MAC(k, id).
    def _create_initial_macaroon_signature(self, key):
        derived_key = self._generate_derived_key(key)
        return self._macaroon_hmac(derived_key, self._identifier)

    def _generate_derived_key(self, key):
        generator_key = b'macaroons-key-generator'
        derived_key = self._hmac(generator_key, key)
        return derived_key

    # key should be unhexlified, data is a string
    def _macaroon_hmac(self, key, data):
        dig = self._hmac(key, data)
        return binascii.hexlify(dig)

    # key should be unhexlified, data is a string
    def _hmac(self, key, data):
        return hmac.new(
            key,
            msg=data.encode('ascii'),
            digestmod=hashlib.sha256
        ).digest()

    # TODO: pack using python struct
    # http://stackoverflow.com/questions/9566061/unspecified-byte-lengths-in-python
    def _packetize(self, key, data):
        PACKET_PREFIX_LENGTH = 4
        # The 2 covers the space and the newline
        packet_size = PACKET_PREFIX_LENGTH + 2 + len(key) + len(data)
        # Ignore the first two chars, 0x
        packet_size_hex = hex(packet_size)[2:]
        header = packet_size_hex.zfill(4)
        packet = header.encode('ascii') + key.encode('ascii') + b' ' + data + b'\n'
        return packet

    def _truncate_or_pad(self, byte_string, size=None):
        if size is None:
            size = 32
        byte_array = bytearray(byte_string)
        length = len(byte_array)
        if length > size:
            return bytes(byte_array[:size])
        elif length < size:
            return bytes(byte_array + b"\0"*(size-length))
        else:
            return byte_string
