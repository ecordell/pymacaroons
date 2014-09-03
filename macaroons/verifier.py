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

    def verify(self, macaroon, key, MS=None):
        compare_macaroon = Macaroon(
            location=macaroon.location,
            identifier=macaroon.identifier,
            key=key
        )
        # verify that first party caveats are met
        for caveat in macaroon.caveats:
            caveatMet = False

            if caveat.caveatId in self.predicates:
                caveatMet = True
            else:
                for callback in self.callbacks:
                    if callback(caveat.caveatId):
                        caveatMet = True

            if caveatMet:
                compare_macaroon.add_first_party_caveat(caveat.caveatId)
            else:
                print('Caveat not met. Invalid macaroon.')

        # TODO: verify third party caveats

        # verify that the signatures are the same
        if macaroon.signature != compare_macaroon.signature:
            print('Signatures do not match')
            return False

        return True
