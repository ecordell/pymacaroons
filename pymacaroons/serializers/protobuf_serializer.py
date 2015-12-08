from pymacaroons.serializers.protobuf.macaroon_pb2 import Macaroon as ProtoMacaroon

from base64 import standard_b64decode, standard_b64encode

class ProtobufSerializer(object):

    def serialize(self, macaroon):
        serialized = ProtoMacaroon()
        serialized.location = macaroon.location
        serialized.id = macaroon.identifier
        for caveat in macaroon.caveats:
            proto_caveat = serialized.caveats.add()
            proto_caveat.id = caveat.caveat_id
            if caveat.first_party():
                proto_caveat.type = ProtoMacaroon.FIRST_PARTY
            else:
                proto_caveat.type = ProtoMacaroon.THIRD_PARTY
                proto_caveat.vid = standard_b64encode(caveat.verification_key_id)
                proto_caveat.location = caveat.location
        serialized.signature = macaroon.signature
        return serialized.SerializeToString()

    def deserialize(self, serialized):
        from pymacaroons.macaroon import Macaroon
        from pymacaroons.caveat import Caveat

        deserialized = ProtoMacaroon()
        deserialized.ParseFromString(serialized)
        caveats = []
        for c in deserialized.caveats:
            if c.type == ProtoMacaroon.FIRST_PARTY:
                caveats.append(Caveat(caveat_id=c.id))
            else:
                caveats.append(Caveat(caveat_id=c.id, verification_key_id=standard_b64decode(c.vid), location=c.location))

        return Macaroon(identifier=deserialized.id, location=deserialized.location, caveats=caveats, signature=deserialized.signature)
