import hmac
import binascii
from base64 import standard_b64decode

from libnacl.secret import SecretBox
from libnacl import crypto_secretbox_NONCEBYTES
from six import PY3

from macaroons.macaroon import Macaroon
from macaroons.raw_macaroon import RawMacaroon
from macaroons.exceptions import (MacaroonInvalidSignatureException,
                                  MacaroonUnmetCaveatException)
from macaroons.utils import (convert_to_bytes,
                             convert_to_string,
                             truncate_or_pad,
                             equals,
                             generate_derived_key,
                             hmac_digest,
                             sign_first_party_caveat,
                             sign_third_party_caveat)


class Verifier(object):

    def __init__(self):
        self.predicates = []
        self.callbacks = []
        self.calculated_signature = None

    def satisfy_exact(self, predicate):
        if predicate is None:
            raise TypeError('Predicate cannot be none.')
        self.predicates.append(convert_to_string(predicate))

    def satisfy_general(self, func):
        if not hasattr(func, '__call__'):
            raise TypeError('General caveat verifiers must be functions.')
        self.callbacks.append(func)

    def verify(self, macaroon, key, discharge_macaroons=None):
        key = generate_derived_key(convert_to_bytes(key))
        return self.verify_discharge(
            macaroon,
            macaroon,
            key,
            discharge_macaroons
        )

    def verify_discharge(self, root, macaroon, key, discharge_macaroons=None):
        self.calculated_signature = hmac_digest(
            key, convert_to_bytes(macaroon.identifier)
        )

        self._verify_caveats(macaroon, discharge_macaroons)

        if root != macaroon:
            self.calculated_signature = binascii.unhexlify(
                root._raw_macaroon._bind_signature(
                    binascii.hexlify(self.calculated_signature)
                )
            )

        if not self._signatures_match(
            macaroon.signature,
            binascii.hexlify(self.calculated_signature)
        ):
            raise MacaroonInvalidSignatureException('Signatures do not match.')

        return True

    def _verify_caveats(self, macaroon, discharge_macaroons):
        for caveat in macaroon.caveats:
            if caveat.first_party():
                caveatMet = self._verify_first_party_caveat(
                    caveat
                )
            else:
                caveatMet = self._verify_third_party_caveat(
                    caveat,
                    macaroon,
                    discharge_macaroons
                )

            if not caveatMet:
                raise MacaroonUnmetCaveatException(
                    'Caveat not met. Unable to satisify: ' + caveat.caveatId
                )

    def _verify_first_party_caveat(self, caveat):
        caveatMet = False
        if caveat.caveatId in self.predicates:
            caveatMet = True
        else:
            for callback in self.callbacks:
                if callback(caveat.caveatId):
                    caveatMet = True
        if caveatMet:
            encode_key = self.calculated_signature
            self.calculated_signature = binascii.unhexlify(
                sign_first_party_caveat(
                    encode_key,
                    convert_to_bytes(caveat.caveatId)
                )
            )
        return caveatMet

    def _verify_third_party_caveat(self,
                                   caveat,
                                   root_macaroon,
                                   discharge_macaroons):
        caveatMet = False

        caveat_macaroon = \
            next((m for m in discharge_macaroons
                  if m.identifier == caveat.caveatId), None)

        if not caveat_macaroon:
            raise MacaroonUnmetCaveatException(
                'Caveat not met. No discharge macaroon found for identifier: '
                + caveat.caveatId
            )

        caveat_key = self._extract_caveat_key(caveat)

        caveat_macaroon_verifier = Verifier()
        caveat_macaroon_verifier.predicates = self.predicates
        caveat_macaroon_verifier.callbacks = self.callbacks

        caveatMet = caveat_macaroon_verifier.verify_discharge(
            root_macaroon,
            caveat_macaroon,
            caveat_key,
            discharge_macaroons
        )
        if caveatMet:
            encode_key = self.calculated_signature
            self.calculated_signature = binascii.unhexlify(
                sign_third_party_caveat(
                    encode_key,
                    convert_to_bytes(caveat.verificationKeyId),
                    convert_to_bytes(caveat.caveatId)
                )
            )
        return caveatMet

    def _extract_caveat_key(self, caveat):
        key = truncate_or_pad(self.calculated_signature)
        box = SecretBox(key=key)
        decoded_vid = standard_b64decode(caveat.verificationKeyId)
        decrypted = box.decrypt(decoded_vid)
        return decrypted

    def _signatures_match(self, s1, s2):
        # uses a constant-time compare
        sig1 = convert_to_bytes(s1)
        sig2 = convert_to_bytes(s2)
        if PY3:
            return hmac.compare_digest(sig1, sig2)
        else:
            return equals(sig1, sig2)
