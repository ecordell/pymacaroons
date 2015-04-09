from pymacaroons.binders import *
from pymacaroons.utils import *


class HashSignaturesBinder1(HashSignaturesBinder):
    def __init__(self, root):
        super(HashSignaturesBinder1, self).__init__(
            root, truncate_or_pad(b'12345')
        )


class HashSignaturesBinder2(HashSignaturesBinder):
    def __init__(self, root):
        super(HashSignaturesBinder2, self).__init__(
            root, truncate_or_pad(b'56789')
        )
