__author__ = 'Evan Cordell'

__version__ = "0.5.1"
__version_info__ = tuple(__version__.split('.'))
__short_version__ = __version__

from .macaroon import Macaroon
from .caveat import Caveat
from .verifier import Verifier
