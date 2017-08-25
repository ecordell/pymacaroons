from __future__ import unicode_literals
import json

from mock import *
from nose.tools import *

from libnacl import crypto_box_NONCEBYTES
from pymacaroons import Macaroon, MACAROON_V1, MACAROON_V2, Verifier
from pymacaroons.serializers import *
from pymacaroons.exceptions import *
from pymacaroons.utils import *


class TestMacaroon(object):

    def setup(self):
        pass

    def test_basic_signature(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        assert_equal(
            m.signature,
            'e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f'
        )

    def test_first_party_caveat(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

    def test_serializing(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it',
            version=MACAROON_V1
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            m.serialize(),
            'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZ\
WQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegR\
K8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'
        )

    def test_serializing_with_binary_v1(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it',
            version=MACAROON_V1
        )
        m.add_first_party_caveat('test = caveat')
        n = Macaroon.deserialize(m.serialize())
        assert_equal(m.identifier, n.identifier)
        assert_equal(m.version, n.version)

    def test_serializing_with_binary_v2(self):
        identifier = base64.b64decode('AK2o+q0Aq9+bONkXw7ky7HAuhCLO9hhaMMc==')
        m = Macaroon(
            location='http://mybank/',
            identifier=identifier,
            key='this is our super secret key; only we should know it',
            version=MACAROON_V2
        )
        m.add_first_party_caveat('test = caveat')
        n = Macaroon.deserialize(m.serialize())
        assert_equal(m.identifier_bytes, n.identifier_bytes)
        assert_equal(m.version, n.version)

    def test_serializing_v1(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it',
            version=MACAROON_V1
        )
        m.add_first_party_caveat('test = caveat')
        n = Macaroon.deserialize(m.serialize())
        assert_equal(m.identifier, n.identifier)
        assert_equal(m.version, n.version)

    def test_serializing_v2(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it',
            version=MACAROON_V2
        )
        m.add_first_party_caveat('test = caveat')
        n = Macaroon.deserialize(m.serialize())
        assert_equal(m.identifier_bytes, n.identifier_bytes)
        assert_equal(m.version, n.version)

    def test_deserializing_invalid(self):
        with assert_raises(MacaroonDeserializationException) as cm:
            Macaroon.deserialize("QA")

    def test_serializing_strips_padding(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it',
            version=MACAROON_V1
        )
        m.add_first_party_caveat('test = acaveat')
        assert_equal(
            m.serialize(),
            # In padded base64, this would end with '=='
            ('MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVz'
             'ZWQgb3VyIHNlY3JldCBrZXkKMDAxN2NpZCB0ZXN0ID0gYWNhdmVhdAowMDJmc2ln'
             'bmF0dXJlIJRJ_V3WNJQnqlVq5eez7spnltwU_AXs8NIRY739sHooCg')
        )

    def test_serializing_max_length_packet(self):
        m = Macaroon(location='test', identifier='blah', key='secret',
                     version=MACAROON_V1)
        m.add_first_party_caveat('x' * 65526)  # exactly 0xFFFF
        assert_not_equal(
            m.serialize(),
            None
        )

    def test_serializing_too_long_packet(self):
        m = Macaroon(location='test', identifier='blah', key='secret',
                     version=MACAROON_V1)
        m.add_first_party_caveat('x' * 65527)  # one byte too long
        assert_raises(
            MacaroonSerializationException,
            m.serialize
        )

    def test_deserializing(self):
        m = Macaroon.deserialize(
            'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaW\
VyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1\
cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'
        )
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

    def test_deserializing_with_binary(self):
        m = Macaroon.deserialize(
            'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaW\
VyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1\
cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'.encode('ascii')
        )
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

    def test_deserializing_accepts_padding(self):
        m = Macaroon.deserialize(
            ('MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVz'
             'ZWQgb3VyIHNlY3JldCBrZXkKMDAxN2NpZCB0ZXN0ID0gYWNhdmVhdAowMDJmc2ln'
             'bmF0dXJlIJRJ_V3WNJQnqlVq5eez7spnltwU_AXs8NIRY739sHooCg==')
        )
        assert_equal(
            m.signature,
            '9449fd5dd6349427aa556ae5e7b3eeca6796dc14fc05ecf0d21163bdfdb07a28'
        )

    def test_serializing_json_v1(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it',
            version=MACAROON_V1
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            json.loads(m.serialize(serializer=JsonSerializer()))['signature'],
            "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67"
        )

    def test_serializing_json_v2_with_binary(self):
        id = base64.b64decode('AK2o+q0Aq9+bONkXw7ky7HAuhCLO9hhaMMc==')
        m = Macaroon(
            location='http://mybank/',
            identifier=id,
            key='this is our super secret key; only we should know it',
            version=MACAROON_V2
        )
        assert_equal(
            json.loads(m.serialize(serializer=JsonSerializer()))['i64'],
            "AK2o-q0Aq9-bONkXw7ky7HAuhCLO9hhaMMc"
        )
        n = Macaroon.deserialize(
            m.serialize(serializer=JsonSerializer()),
            serializer=JsonSerializer()
        )
        assert_equal(m.identifier_bytes, n.identifier_bytes)

    def test_serializing_json_v2(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it',
            version=MACAROON_V2
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            json.loads(m.serialize(serializer=JsonSerializer()))['s64'],
            "GXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWc"
        )

    def test_deserializing_json_v1(self):
        m = Macaroon.deserialize(
            '{"location": "http://mybank/", "identifier": "we used our secret \
key", "signature": "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c2\
3dbd67", "caveats": [{"cl": null, "cid": "test = caveat", "vid": null}]}',
            serializer=JsonSerializer()
        )
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

    def test_deserializing_json_v2(self):
        m = Macaroon.deserialize(
            '{"l": "http://mybank/", "i": "we used our secret key", "s": '
            '"197bac7a044af33332"'
            ', "c": [{"l": null, "i": "test = caveat", "v": null}]}',
            serializer=JsonSerializer()
        )
        assert_equal(
            m.signature_bytes,
            binascii.hexlify(b'197bac7a044af33332')
        )

    def test_serializing_deserializing_json_v1(self):
        self._serializing_deserializing_json_with_version(MACAROON_V1)

    def test_serializing_deserializing_json_v2(self):
        self._serializing_deserializing_json_with_version(MACAROON_V2)

    def _serializing_deserializing_json_with_version(self, version):
        m = Macaroon(
            location='http://test/',
            identifier='first',
            key='secret_key_1',
            version=version
        )
        m.add_first_party_caveat('test = caveat')
        n = Macaroon.deserialize(
            m.serialize(serializer=JsonSerializer()),
            serializer=JsonSerializer()
        )
        assert_equal(m.signature, n.signature)

    def test_verify_first_party_exact_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        v = Verifier()
        v.satisfy_exact('test = caveat')
        verified = v.verify(
            m,
            'this is our super secret key; only we should know it'
        )
        assert_true(verified)

    def test_verify_first_party_general_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('general caveat')

        def general_caveat_validator(predicate):
            return predicate == 'general caveat'

        v = Verifier()
        v.satisfy_general(general_caveat_validator)
        verified = v.verify(
            m,
            'this is our super secret key; only we should know it'
        )
        assert_true(verified)

    @patch('libnacl.secret.libnacl.utils.rand_nonce')
    def test_third_party_caveat(self, rand_nonce):
        # use a fixed nonce to ensure the same signature
        rand_nonce.return_value = truncate_or_pad(
            b'\0',
            size=crypto_box_NONCEBYTES
        )
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)
        assert_equal(
            m.signature,
            'd27db2fd1f22760e4c3dae8137e2d8fc1df6c0741c18aed4b97256bf78d1f55c'
        )

    def test_serializing_macaroon_with_first_and_third_caveats_v1(self):
        self._serializing_macaroon_with_first_and_third_caveats(MACAROON_V1)

    def test_serializing_macaroon_with_first_and_third_caveats_v2(self):
        self._serializing_macaroon_with_first_and_third_caveats(MACAROON_V2)

    def _serializing_macaroon_with_first_and_third_caveats(self, version):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice',
            version=version
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)

        n = Macaroon.deserialize(m.serialize())

        assert_equal(
            m.signature,
            n.signature
        )

    @patch('libnacl.secret.libnacl.utils.rand_nonce')
    def test_prepare_for_request(self, rand_nonce):
        # use a fixed nonce to ensure the same signature
        rand_nonce.return_value = truncate_or_pad(
            b'\0',
            size=crypto_box_NONCEBYTES
        )
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat(
            'http://auth.mybank/',
            caveat_key,
            identifier
        )

        discharge = Macaroon(
            location='http://auth.mybank/',
            key=caveat_key,
            identifier=identifier
        )
        discharge.add_first_party_caveat('time < 2015-01-01T00:00')
        protected = m.prepare_for_request(discharge)
        assert_equal(
            protected.signature,
            '2eb01d0dd2b4475330739140188648cf25dda0425ea9f661f1574ca0a9eac54e'
        )

    def test_verify_third_party_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)

        discharge = Macaroon(
            location='http://auth.mybank/',
            key=caveat_key,
            identifier=identifier
        )
        discharge.add_first_party_caveat('time < 2015-01-01T00:00')
        protected = m.prepare_for_request(discharge)

        v = Verifier()
        v.satisfy_exact('account = 3735928559')
        v.satisfy_exact('time < 2015-01-01T00:00')
        verified = v.verify(
            m,
            'this is a different super-secret key; \
never use the same secret twice',
            discharge_macaroons=[protected]
        )
        assert_true(verified)

    @patch('libnacl.secret.libnacl.utils.rand_nonce')
    def test_inspect(self, rand_nonce):
        # use a fixed nonce to ensure the same signature
        rand_nonce.return_value = truncate_or_pad(
            b'\0',
            size=crypto_box_NONCEBYTES
        )
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)
        assert_equal(m.inspect(), (
            'location http://mybank/\n'
            'identifier we used our secret key\n'
            'cid test = caveat\n'
            'cid this was how we remind auth of key/pred\n'
            'vid AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA68NYajhiFuHnKGSNcVhkAwgbs0VZ0yK2o+q0Aq9+bONkXw7ky7HAuhCLO9hhaMMc\n'
            'cl http://auth.mybank/\n'
            'signature 7a9289bfbb92d725f748bbcb4f3e04e56b7021513ebeed8411bfba10a16a662e'))
