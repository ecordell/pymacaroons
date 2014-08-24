
class Verifier:

    def satisfy_exact(self, pred):
        pass

    def satisfy_general(self, func):
        pass

    def verify(self, Macaroon M, bytes key, MS=None):
        pass

    def verify_unsafe(self, Macaroon M, bytes key, MS=None):
        pass
