import json
from base64 import standard_b64decode
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
                caveat_id=c['cid'],
                verification_key_id=(
                    standard_b64decode(c['vid']) if c['vid'] else None
                ),
                location=c['cl']
            )
            caveats.append(caveat)

        return Macaroon(
            location=deserialized['location'],
            identifier=deserialized['identifier'],
            caveats=caveats,
            signature=deserialized['signature']
        )
