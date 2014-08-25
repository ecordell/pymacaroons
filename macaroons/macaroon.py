import hmac
import hashlib
import binascii
import base64

from caveat import Caveat


class Macaroon:

    # TODO
    def __init__(self,
                 location=None,
                 identifier=None,
                 key=None,
                 bytes=None):
        self._bytes = bytes
        self._caveats = []
        # TODO: validations, only loc, id, key or bytes
        if location and identifier and key:
            self._location = location
            self._identifier = identifier
            self._key = key
            self._signature = self._create_initial_macaroon_signature()
            self._bytes = None
        elif self._bytes:
            # TODO
            pass
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
        pass

    # Concatenates location, id, all caveats, and signature,
    # and then base64 encodes them
    def serialize(self):
        combined = self._packetize('location', self.location)
        combined += self._packetize('identifier', self.identifier)

        # TODO: list comprehension
        for caveat in self.caveats:
            combined += self._packetize('cid', caveat.caveatId)

            if caveat.verificationKeyId and caveat.location:
                combined += self._packetize('vid', caveat.verificationKeyId)
                combined += self._packetize('cl', caveat.location)

        combined += self._packetize(
            'signature',
            binascii.unhexlify(self.signature)
        )
        return base64.urlsafe_b64encode(combined)

    # TODO: pack using python struct
    def _packetize(self, key, data):
        PACKET_PREFIX_LENGTH = 4
        # The 2 covers the space and the newline
        packet_size = PACKET_PREFIX_LENGTH + 2 + len(key) + len(data)
        # Ignore the first two chars, 0x
        packet_size_hex = hex(packet_size)[2:]
        header = packet_size_hex.zfill(4)
        packet = header + key + ' ' + data + '\n'
        return packet

    def serialize_json(self):
        pass

    def inspect(self):
        pass

    # TODO
    def is_same(self, macaroon):
        pass

    def third_party_caveats(self):
        pass

    # TODO (only needed for third party)
    def prepare_for_request(self, macaroon):
        pass

    # The existing macaroon signature is the key for hashing the
    # caveat being added. This new hash becomes the signature of
    # the macaroon with caveat added.
    def add_first_party_caveat(self, predicate):
        caveat = Caveat(caveatId=predicate)
        self._caveats.append(caveat)
        encode_key = binascii.unhexlify(self.signature)
        self.signature = self._macaroon_hmac(encode_key, predicate)
        return self

    # TODO
    def add_third_party_caveat(self,
                               location,
                               key,
                               key_id):
        pass

    # Given a high-entropy root key _key and an identifier id, the function
    # _create_initial_macaroon_signature(_location, _identifier, _key) returns
    # valid signature  sig = MAC(k, id).
    def _create_initial_macaroon_signature(self):
        generator_key = b'macaroons-key-generator'
        derived_key = hmac.new(
            generator_key,
            msg=self._key.encode('ascii'),
            digestmod=hashlib.sha256
        ).digest()
        return self._macaroon_hmac(derived_key, self._identifier)

    # key should be unhexlified, data is a string
    def _macaroon_hmac(self, key, data):
        dig = hmac.new(
            key,
            msg=data.encode('ascii'),
            digestmod=hashlib.sha256
        ).digest()
        return binascii.hexlify(dig)
