__author__ = 'Evan Cordell'

__version__ = "0.7.0"
__version_info__ = tuple(__version__.split('.'))
__short_version__ = __version__

from .caveat import Caveat
from .macaroon import Macaroon
from .verifier import Verifier

__all__ = [
    'Macaroon',
    'Caveat',
    'Verifier',
]
