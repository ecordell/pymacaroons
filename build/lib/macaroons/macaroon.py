
class Macaroon:

    def validate(self):
        pass

    @property
    def location(self):
        pass

    @property
    def identifier(self):
        pass

    @property
    def signature(self):
        pass

    def copy(self):
        pass

    def serialize(self):
        pass

    def serialize_json(self):
        pass

    def inspect(self):
        pass

    def is_same(self, Macaroon M):
        pass

    def third_party_caveats(self):
        pass

    def prepare_for_request(self, Macaroon D):
        pass

    def add_first_party_caveat(self, bytes predicate):
        pass

    def add_third_party_caveat(self,
                               bytes _location,
                               bytes _key,
                               bytes _key_id):
        pass
