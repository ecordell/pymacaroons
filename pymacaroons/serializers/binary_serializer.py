from __future__ import unicode_literals

import binascii
import struct
from base64 import urlsafe_b64encode, urlsafe_b64decode

from pymacaroons.utils import convert_to_bytes
from pymacaroons.serializers.base_serializer import BaseSerializer


class BinarySerializer(BaseSerializer):

    PACKET_PREFIX_LENGTH = 4

    def serialize(self, macaroon):
        raw_macaroon = macaroon._raw_macaroon
        combined = self._packetize(b'location', raw_macaroon.location)
        combined += self._packetize(b'identifier', raw_macaroon.identifier)

        for caveat in raw_macaroon.caveats:
            combined += self._packetize(b'cid', caveat._caveatId)

            if caveat._verificationKeyId and caveat._location:
                combined += self._packetize(b'vid', caveat._verificationKeyId)
                combined += self._packetize(b'cl', caveat._location)

        combined += self._packetize(
            b'signature',
            binascii.unhexlify(raw_macaroon._signature)
        )
        return urlsafe_b64encode(combined).decode('ascii')

    def deserialize(self, serialized):
        from pymacaroons.raw_macaroon import RawMacaroon
        from pymacaroons.macaroon import Macaroon
        from pymacaroons.caveat import Caveat
        from pymacaroons.exceptions import MacaroonDeserializationException

        raw_macaroon = RawMacaroon()
        decoded = urlsafe_b64decode(convert_to_bytes(
            serialized + "=" * (-len(serialized) % 4)
        ))

        index = 0

        while index < len(decoded):
            packet_length = int(
                struct.unpack(
                    b"4s",
                    decoded[index:index + self.PACKET_PREFIX_LENGTH]
                )[0],
                16
            )
            packet = decoded[
                index + self.PACKET_PREFIX_LENGTH:index + packet_length
            ]

            key, value = self._depacketize(packet)

            if key == b'location':
                raw_macaroon._location = value
            elif key == b'identifier':
                raw_macaroon._identifier = value
            elif key == b'cid':
                raw_macaroon.caveats.append(Caveat(caveatId=value))
            elif key == b'vid':
                raw_macaroon.caveats[-1].verificationKeyId = value
            elif key == b'cl':
                raw_macaroon.caveats[-1].location = value
            elif key == b'signature':
                raw_macaroon._signature = convert_to_bytes(
                    binascii.hexlify(value)
                )
            else:
                raise MacaroonDeserializationException(
                    'Key {key} not valid key for this format. Value: '.format(
                        key=key, value=value
                    )
                )

            index = index + packet_length

        m = Macaroon(location=b'\0', identifier=b'\0', key=b'\0')
        m._raw_macaroon = raw_macaroon
        return m

    def _packetize(self, key, data):
        # The 2 covers the space and the newline
        packet_size = self.PACKET_PREFIX_LENGTH + 2 + len(key) + len(data)
        # Ignore the first two chars, 0x
        packet_size_hex = hex(packet_size)[2:]
        header = packet_size_hex.zfill(4).encode('ascii')
        packet_content = key + b' ' + data + b'\n'
        packet = struct.pack(
            convert_to_bytes("4s%ds" % len(packet_content)),
            header,
            packet_content
        )
        return packet

    def _depacketize(self, packet):
        key = packet.split(b' ')[0]
        value = packet[len(key) + 1:-1]
        return (key, value)
