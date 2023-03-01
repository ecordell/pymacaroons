from __future__ import unicode_literals

from nacl.bindings import crypto_box_NONCEBYTES
from pymacaroons import Macaroon, Verifier
from pymacaroons.caveat_delegates import EncryptedFirstPartyCaveatDelegate, EncryptedFirstPartyCaveatVerifierDelegate
from pymacaroons.field_encryptors import SecretBoxEncryptor
from pymacaroons.utils import truncate_or_pad


class TestEncryptedFieldsMacaroon(object):

    def setup(self):
        pass

    def test_encrypted_first_party_caveat(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        encryptor = SecretBoxEncryptor(nonce=truncate_or_pad(
            b'\0',
            size=crypto_box_NONCEBYTES
        ))
        m.first_party_caveat_delegate = EncryptedFirstPartyCaveatDelegate(field_encryptor=encryptor)
        m.add_first_party_caveat('test = caveat', encrypted=True)
        assert\
            m.signature ==\
            'a443bc61e8f45dca4f0c441d6cfde90b804cebb0b267aab60de1ec2ab8cc8522'

    def test_verify_encrypted_first_party_exact_caveats(self):
        m = Macaroon(
            location='http://mybank/',
            identifier='we used our secret key',
            key='this is our super secret key; only we should know it'
        )
        m.first_party_caveat_delegate = EncryptedFirstPartyCaveatDelegate()
        m.add_first_party_caveat('test = caveat', encrypted=True)

        v = Verifier()
        v.first_party_caveat_verifier_delegate = EncryptedFirstPartyCaveatVerifierDelegate()
        v.satisfy_exact('test = caveat')
        verified = v.verify(
            m,
            'this is our super secret key; only we should know it'
        )
        assert verified
