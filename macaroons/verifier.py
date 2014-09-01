from .macaroon import Macaroon


class Verifier:

    predicates = []
    callbacks = []

    def satisfy_exact(self, predicate):
        # TODO: validate predicate
        self.predicates.append(predicate)

    def satisfy_general(self, func):
        pass

    def verify(self, macaroon, key, MS=None):
        compare_macaroon = Macaroon(
            location=macaroon.location,
            identifier=macaroon.identifier,
            key=key
        )
        # verify that first party caveats are met
        for caveat in macaroon.caveats:
            if caveat.caveatId not in self.predicates:
                print('Caveat not found. Invalid macaroon.')
                return False
            else:
                compare_macaroon.add_first_party_caveat(caveat.caveatId)

        # TODO: verify third party caveats

        # verify that the signatures are the same
        if macaroon.signature != compare_macaroon.signature:
            print('Signatures do not match')
            return False

        return True
