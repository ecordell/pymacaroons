from __future__ import unicode_literals

import binascii
import struct
from base64 import urlsafe_b64encode, urlsafe_b64decode

from pymacaroons.utils import convert_to_bytes
from pymacaroons.serializers.base_serializer import BaseSerializer
from pymacaroons.exceptions import MacaroonSerializationException


class BinarySerializer(BaseSerializer):

    PACKET_PREFIX_LENGTH = 4

    def serialize(self, macaroon):
        combined = self._packetize(b'location', macaroon.location)
        combined += self._packetize(b'identifier', macaroon.identifier)

        for caveat in macaroon.caveats:
            combined += self._packetize(b'cid', caveat._caveat_id)

            if caveat._verification_key_id and caveat._location:
                combined += self._packetize(
                    b'vid', caveat._verification_key_id)
                combined += self._packetize(b'cl', caveat._location)

        combined += self._packetize(
            b'signature',
            binascii.unhexlify(macaroon.signature_bytes)
        )
        return urlsafe_b64encode(combined).decode('ascii').rstrip('=')

    def deserialize(self, serialized):
        from pymacaroons.macaroon import Macaroon
        from pymacaroons.caveat import Caveat
        from pymacaroons.exceptions import MacaroonDeserializationException

        macaroon = Macaroon()

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
                macaroon.location = value
            elif key == b'identifier':
                macaroon.identifier = value
            elif key == b'cid':
                macaroon.caveats.append(Caveat(caveat_id=value))
            elif key == b'vid':
                macaroon.caveats[-1].verification_key_id = value
            elif key == b'cl':
                macaroon.caveats[-1].location = value
            elif key == b'signature':
                macaroon.signature = binascii.hexlify(value)
            else:
                raise MacaroonDeserializationException(
                    'Key {key} not valid key for this format. '
                    'Value: {value}'.format(
                        key=key, value=value
                    )
                )

            index = index + packet_length

        return macaroon

    def _packetize(self, key, data):
        # The 2 covers the space and the newline
        packet_size = self.PACKET_PREFIX_LENGTH + 2 + len(key) + len(data)
        # Ignore the first two chars, 0x
        packet_size_hex = hex(packet_size)[2:]

        if packet_size > 65535:
            raise MacaroonSerializationException(
                'Packet too long for serialization. '
                'Max length is 0xFFFF (65535). '
                'Packet length: 0x{hex_length} ({length}) '
                'Key: {key}'.format(
                    key=key,
                    hex_length=packet_size_hex,
                    length=packet_size
                )
            )

        header = packet_size_hex.zfill(4).encode('ascii')
        packet_content = key + b' ' + convert_to_bytes(data) + b'\n'
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
