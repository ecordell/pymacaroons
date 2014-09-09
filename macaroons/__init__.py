from macaroons.macaroon import Macaroon
from macaroons.verifier import Verifier

VERSION = (0, 1, 8)
__version__ = '.'.join(str(x) for x in VERSION)


__all__ = [
    'VERSION',
    '__version__',
    'Macaroon',
    'Verifier',
]
