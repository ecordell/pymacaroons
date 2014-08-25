class Caveat:

    def __init__(self,
                 caveatId=None,
                 verificationKeyId=None,
                 location=None):
        # TODO: raise exceptions for invalid init values
        self._caveatId = caveatId
        self._verificationKeyId = verificationKeyId
        self._location = location

    @property
    def caveatId(self):
        return self._caveatId

    @property
    def verificationKeyId(self):
        return self._verificationKeyId

    @property
    def location(self):
        return self._location
