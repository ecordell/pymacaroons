from __future__ import unicode_literals
import json

from mock import *
from nose.tools import *


from macaroons.macaroon import Macaroon
from macaroons.verifier import Verifier
from macaroons.utils import *


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
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            m.serialize(),
            'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZ\
WQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegR\
K8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'
        )

    def test_deserializing(self):
        m = Macaroon.from_binary(
            'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaW\
VyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1\
cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'
        )
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

    def test_serializing_json(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.add_first_party_caveat('test = caveat')
        assert_equal(
            json.loads(m.serialize_json())['signature'],
            "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67"
        )

    def test_deserializing_json(self):
        m = Macaroon.from_json(
            '{"location": "http://mybank/", "identifier": "we used our secret \
key", "signature": "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c2\
3dbd67", "caveats": [{"cl": null, "cid": "test = caveat", "vid": null}]}'
        )
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

    def test_serializing_deserializing_json(self):
        m = Macaroon(
            location='http://test/',
            identifier='first',
            key='secret_key_1'
        )
        m.add_first_party_caveat('test = caveat')
        m.serialize_json()
        n = Macaroon.from_json(m.serialize_json())
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

    def test_third_party_caveat(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        predicate = 'user = Alice'
        identifier = 'this was how we remind auth of key/pred'
        # use a fixed nonce to ensure the same signature
        m._raw_macaroon._add_third_party_caveat_direct(
            'http://auth.mybank/',
            caveat_key.encode('ascii'),
            identifier,
            nonce=truncate_or_pad(b'\0', size=24)
        )
        assert_equal(
            m.signature,
            '3cd1effbec018d6cbc1d17384d4924e3a708f25c2c0404d1a6af4f0578867fd0'
        )

    def test_serializing_macaroon_with_first_and_third_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        predicate = 'user = Alice'
        identifier = 'this was how we remind auth of key/pred'
        m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)

        n = Macaroon.from_binary(m.serialize())

        assert_equal(
            m.signature,
            n.signature
        )

    def test_prepare_for_request(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our other secret key',
            key='this is a different super-secret key; \
never use the same secret twice'
        )
        m.add_first_party_caveat('account = 3735928559')
        caveat_key = '4; guaranteed random by a fair toss of the dice'
        predicate = 'user = Alice'
        identifier = 'this was how we remind auth of key/pred'
        # use a fixed nonce to ensure the same signature
        m._raw_macaroon._add_third_party_caveat_direct(
            'http://auth.mybank/',
            caveat_key.encode('ascii'),
            identifier,
            nonce=truncate_or_pad(b'\0', size=24)
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
            '753236901d08e9610506e09ec04fb61313bae04ad6b1babf4c44de7fe56afbc1'
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
        predicate = 'user = Alice'
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
