from __future__ import unicode_literals

from mock import *
from nose.tools import *

from macaroons import *
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
        m = Macaroon(
            serialized='MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaW\
VyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1\
cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'
        )
        assert_equal(
            m.signature,
            '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'
        )

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
            '39420840b3a0ac50340cd235c3a77ecb11dcbc2e5d0145f60796a56d378bd997'
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

        n = Macaroon(serialized=m.serialize())
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
            '4eb7f2b310a302fa998a884055b4bd1b86e764a2ddf4e8c806579ec855328965'
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
