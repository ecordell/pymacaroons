import json

from pymacaroons.utils import convert_to_string, convert_to_bytes


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
        from pymacaroons.raw_macaroon import RawMacaroon
        from pymacaroons.macaroon import Macaroon
        from pymacaroons.caveat import Caveat

        raw_macaroon = RawMacaroon()

        deserialized = json.loads(convert_to_string(serialized))
        raw_macaroon._location = deserialized['location']
        raw_macaroon._identifier = deserialized['identifier']
        for c in deserialized['caveats']:
            caveat = Caveat(
                caveatId=c['cid'],
                verificationKeyId=c['vid'],
                location=c['cl']
            )
            raw_macaroon._caveats.append(caveat)
        raw_macaroon._signature = convert_to_bytes(deserialized['signature'])
        m = Macaroon(location=b'\0', identifier=b'\0', key=b'\0')
        m._raw_macaroon = raw_macaroon
        return m
