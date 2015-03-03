import json

from pymacaroons.utils import convert_to_string


class JsonSerializer(object):

    def serialize(self, macaroon):
        serialized = {
            'location': macaroon.location,
            'identifier': macaroon.identifier,
            'caveats': [caveat.to_dict() for caveat in macaroon.caveats],
            'signature': macaroon.signature
        }
        return json.dumps(serialized)

    def deserialize(self, serialized):
        from pymacaroons.macaroon import Macaroon
        from pymacaroons.caveat import Caveat

        caveats = []
        deserialized = json.loads(convert_to_string(serialized))

        for c in deserialized['caveats']:
            caveat = Caveat(
                caveatId=c['cid'],
                verificationKeyId=c['vid'],
                location=c['cl']
            )
            caveats.append(caveat)

        return Macaroon(
            location=deserialized['location'],
            identifier=deserialized['identifier'],
            caveats=caveats,
            signature=deserialized['signature']
        )
