import hmac
import hashlib
import base64
import binascii


class Macaroon:

    # TODO
    def __init__(self,
                 location=None,
                 identifier=None,
                 key=None,
                 bytes=None):
        self._bytes = bytes
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

    # TODO
    def validate(self):
        pass

    def copy(self):
        pass

    # TODO
    def serialize(self):
        pass

    def serialize_json(self):
        pass

    def inspect(self):
        pass

    # TODO
    def is_same(self, macaroon):
        pass

    def third_party_caveats(self):
        pass

    # TODO?
    def prepare_for_request(self, macaroon):
        pass

    # TODO
    def add_first_party_caveat(self, predicate):
        pass

    def add_third_party_caveat(self,
                               _location,
                               _key,
                               _key_id):
        pass

    # Given a high-entropy root key _key and an identifier id, the function
    # _create_initial_macaroon_signature(_location, _identifier, _key) returns
    # valid signature  sig = MAC(k, id).
    def _create_initial_macaroon_signature(self):
        return self._macaroon_hmac(self._key, self._identifier)

    def _macaroon_hmac(self, key, data):
        generator_key = b'macaroons-key-generator'
        derived_key = hmac.new(
            generator_key,
            msg=key.encode('ascii'),
            digestmod=hashlib.sha256
        ).digest()
        dig = hmac.new(
            derived_key,
            msg=data.encode('ascii'),
            digestmod=hashlib.sha256
        ).digest()
        return binascii.hexlify(dig)


    def _add_caveat_helper(self):
       pass

    # TODO: no longer needed?
    def _truncate_or_pad(self, byte_string):
        byte_array = bytearray(byte_string)
        length = len(byte_array)
        if length > 32:
            return bytes(byte_array[:32])
        elif length < 32:
            return bytes(byte_array + b"\0"*(32-length))
        else:
            return byte_string
