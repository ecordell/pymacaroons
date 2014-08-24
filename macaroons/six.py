import sys


__all__ = [
    'PY2',
    'string_type',
    'text_type',
    'quote_plus',
    'urljoin',
    'urlparse',
    'iterkeys',
    'itervalues',
    'iteritems',
]


PY2 = sys.version_info[0] < 3


if PY2:
    from urllib import quote_plus
    from urlparse import urljoin, urlparse

    string_type = basestring
    text_type = unicode

    _iterkeys = 'iterkeys'
    _itervalues = 'itervalues'
    _iteritems = 'iteritems'
else:
    from urllib.parse import quote_plus, urljoin, urlparse

    string_type = str
    text_type = str

    _iterkeys = 'keys'
    _itervalues = 'values'
    _iteritems = 'items'


def iterkeys(d):
    """
    Return an iterator over the keys of a dictionary.
    """
    return iter(getattr(d, _iterkeys)())


def itervalues(d):
    """
    Return an iterator over the values of a dictionary.
    """
    return iter(getattr(d, _itervalues)())


def iteritems(d):
    """
    Return an iterator over the (key, value) pairs of a dictionary.
    """
    return iter(getattr(d, _iteritems)())
