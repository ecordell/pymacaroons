import hmac
import base64

from libnacl.secret import SecretBox
from libnacl import crypto_secretbox_NONCEBYTES
from streql import equals

from .macaroon import Macaroon


class Verifier:

    predicates = []
    callbacks = []

    def satisfy_exact(self, predicate):
        # TODO: validate predicate
        self.predicates.append(predicate)

    def satisfy_general(self, func):
        # TODO: validate func
        # TODO: support more direct general caveats?
        # for example matching on prefixes?
        self.callbacks.append(func)

    def verify(self, macaroon, key, discharge_macaroons=None):
        compare_macaroon = Macaroon(
            location=macaroon.location,
            identifier=macaroon.identifier,
            key=key
        )

        self._verify_caveats(macaroon, compare_macaroon, discharge_macaroons)

        if not self._signatures_match(macaroon, compare_macaroon):
            print('Signatures do not match')
            return False

        return True

    # Discharge macaroons are bound to the root, extra steps to calculate the signature
    def verify_discharge(self, root, macaroon, key, discharge_macaroons=None):
        compare_macaroon = Macaroon(
            location=macaroon.location,
            identifier=macaroon.identifier,
            signature=macaroon._macaroon_hmac(key, macaroon.identifier)
        )

        self._verify_caveats(macaroon, compare_macaroon, discharge_macaroons)

        compare_macaroon = root.prepare_for_request(compare_macaroon)

        if not self._signatures_match(macaroon, compare_macaroon):
            print('Signatures do not match')
            return False

        return True

    def _verify_caveats(self, macaroon, compare_macaroon, discharge_macaroons):
        for caveat in macaroon.caveats:
            if caveat.first_party():
                caveatMet = self._verify_first_party_caveat(caveat, compare_macaroon)
            else:
                caveatMet = self._verify_third_party_caveat(caveat, macaroon, compare_macaroon, discharge_macaroons)

            if not caveatMet:
                print('Caveat not met. Invalid macaroon.')

    def _verify_first_party_caveat(self, caveat, compare_macaroon):
        caveatMet = False
        if caveat.caveatId in self.predicates:
            caveatMet = True
        else:
            for callback in self.callbacks:
                if callback(caveat.caveatId):
                    caveatMet = True
        if caveatMet:
            compare_macaroon.add_first_party_caveat(caveat.caveatId)
        return caveatMet

    def _verify_third_party_caveat(self, caveat, root_macaroon, compare_macaroon, discharge_macaroons):
        caveatMet = False

        caveat_macaroon = next((m for m in discharge_macaroons if m.identifier == caveat.caveatId), None)
        if not caveat_macaroon:
            print('Caveat not met. No discharge macaroon found for identifier: ' + caveat.caveatId)

        caveat_key, nonce = self._extract_caveat_key(compare_macaroon, caveat)

        caveat_macaroon_verifier = Verifier()
        caveat_macaroon_verifier.predicates = self.predicates
        caveat_macaroon_verifier.callbacks = self.callbacks

        caveatMet = caveat_macaroon_verifier.verify_discharge(root_macaroon, caveat_macaroon, caveat_key, discharge_macaroons)
        if caveatMet:
            compare_macaroon._add_third_party_caveat_direct(caveat.location, caveat_key, caveat.caveatId, nonce=nonce)
        return caveatMet

    def _extract_caveat_key(self, compare_macaroon, caveat):
        key = compare_macaroon._truncate_or_pad(compare_macaroon.signature)
        box = SecretBox(key=key)
        decoded_vid = base64.standard_b64decode(caveat.verificationKeyId)
        nonce = decoded_vid[:crypto_secretbox_NONCEBYTES]
        decrypted = box.decrypt(decoded_vid)
        return decrypted, nonce

    def _signatures_match(self, m1, m2):
        # uses a constant-time compare
        return equals(m1.signature, m2.signature)
