from macaroons.utils import convert_to_string, convert_to_bytes


class Caveat(object):

    def __init__(self,
                 caveatId=None,
                 verificationKeyId=None,
                 location=None):
        self.caveatId = convert_to_bytes(caveatId)
        self.verificationKeyId = convert_to_bytes(verificationKeyId)
        self.location = convert_to_bytes(location)

    @property
    def caveatId(self):
        return convert_to_string(self._caveatId)

    @property
    def verificationKeyId(self):
        return convert_to_string(self._verificationKeyId)

    @property
    def location(self):
        return convert_to_string(self._location)

    @caveatId.setter
    def caveatId(self, value):
        self._caveatId = convert_to_bytes(value)

    @verificationKeyId.setter
    def verificationKeyId(self, value):
        self._verificationKeyId = convert_to_bytes(value)

    @location.setter
    def location(self, value):
        self._location = convert_to_bytes(value)

    def first_party(self):
        return self._verificationKeyId is None

    def third_party(self):
        return self._verificationKeyId is not None

    def to_dict(self):
        serialized = {
            'cid': self.caveatId,
            'vid': self.verificationKeyId,
            'cl': self.location
        }
        return serialized
