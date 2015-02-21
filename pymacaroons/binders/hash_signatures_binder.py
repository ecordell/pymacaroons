import binascii

from pymacaroons.binders.base_binder import BaseBinder
from pymacaroons.utils import hmac_concat, truncate_or_pad, convert_to_bytes


class HashSignaturesBinder(BaseBinder):

    def bind_signature(self, signature):
        return hmac_concat(
            truncate_or_pad(b'\0'),
            binascii.unhexlify(convert_to_bytes(self.root.signature)),
            binascii.unhexlify(convert_to_bytes(signature))
        )
