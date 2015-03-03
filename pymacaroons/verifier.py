import binascii
from base64 import standard_b64decode

try:
    # py2.7.7+ and py3.3+ have native comparison support
    from hmac import compare_digest as constant_time_compare
except ImportError:
    from pymacaroons.utils import equals as constant_time_compare

from libnacl.secret import SecretBox

from pymacaroons.binders import HashSignaturesBinder
from pymacaroons.exceptions import (MacaroonInvalidSignatureException,
                                    MacaroonUnmetCaveatException)
from pymacaroons.utils import (convert_to_bytes,
                               convert_to_string,
                               truncate_or_pad,
                               generate_derived_key,
                               hmac_digest,
                               sign_first_party_caveat,
                               sign_third_party_caveat)


class Verifier(object):

    def __init__(self, default_binder_class=None, discharge_binders=None):
        self.predicates = []
        self.callbacks = []
        self.calculated_signature = None
        self.binder_class = default_binder_class or HashSignaturesBinder
        self.discharge_binders = discharge_binders or {}

    def satisfy_exact(self, predicate):
        if predicate is None:
            raise TypeError('Predicate cannot be none.')
        self.predicates.append(convert_to_string(predicate))

    def satisfy_general(self, func):
        if not hasattr(func, '__call__'):
            raise TypeError('General caveat verifiers must be callable.')
        self.callbacks.append(func)

    def verify(self, macaroon, key, discharge_macaroons=None):
        key = generate_derived_key(convert_to_bytes(key))
        return self.verify_discharge(
            macaroon,
            macaroon,
            key,
            discharge_macaroons
        )

    def verify_discharge(self, root, discharge, key,
                         discharge_macaroons=None, binder_class=None):
        self.calculated_signature = hmac_digest(
            key, discharge._identifier
        )

        self._verify_caveats(discharge, discharge_macaroons)

        if root != discharge:
            binder_class = binder_class or self.binder_class
            self.calculated_signature = binascii.unhexlify(
                binder_class(root).bind_signature(
                    binascii.hexlify(self.calculated_signature)
                )
            )

        if not self._signatures_match(
            discharge.signature,
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
                    caveat._caveatId
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
            discharge_macaroons=discharge_macaroons,
            binder_class=(self.discharge_binders.get(caveat.caveatId) or
                          self.discharge_binders.get(caveat.location))
        )
        if caveatMet:
            encode_key = self.calculated_signature
            self.calculated_signature = binascii.unhexlify(
                sign_third_party_caveat(
                    encode_key,
                    caveat._verificationKeyId,
                    caveat._caveatId
                )
            )
        return caveatMet

    def _extract_caveat_key(self, caveat):
        key = truncate_or_pad(self.calculated_signature)
        box = SecretBox(key=key)
        decoded_vid = standard_b64decode(
            caveat._verificationKeyId
        )
        decrypted = box.decrypt(decoded_vid)
        return decrypted

    def _signatures_match(self, s1, s2):
        sig1 = convert_to_string(s1)
        sig2 = convert_to_string(s2)
        return constant_time_compare(sig1, sig2)
