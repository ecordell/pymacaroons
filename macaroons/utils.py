from hashlib import sha256
import hmac
import binascii

from six import text_type, binary_type


def convert_to_bytes(string):
    if string is None:
        return None
    if type(string) is text_type:
        return string.encode('ascii')
    elif type(string) is binary_type:
        return string
    else:
        raise TypeError("Must be a string or bytes object.")


def convert_to_string(bytes):
    if bytes is None:
        return None
    if type(bytes) is text_type:
        return bytes
    elif type(bytes) is binary_type:
        return bytes.decode('ascii')
    else:
        raise TypeError("Must be a string or bytes object.")


def truncate_or_pad(byte_string, size=None):
    if size is None:
        size = 32
    byte_array = bytearray(byte_string)
    length = len(byte_array)
    if length > size:
        return bytes(byte_array[:size])
    elif length < size:
        return bytes(byte_array + b"\0"*(size-length))
    else:
        return byte_string


def generate_derived_key(key):
    return hmac_digest(b'macaroons-key-generator', key)


def hmac_digest(key, data):
    return hmac.new(
        key,
        msg=data,
        digestmod=sha256
    ).digest()


def sign_first_party_caveat(signature, predicate):
    return binascii.hexlify(hmac_digest(signature, predicate))


def sign_third_party_caveat(signature, verification_id, caveat_id):
    verification_id_hash = hmac_digest(signature, verification_id)
    caveat_id_hash = hmac_digest(signature, caveat_id)
    combined = verification_id_hash + caveat_id_hash
    return binascii.hexlify(hmac_digest(signature, combined))


def equals(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.

    For the sake of simplicity, this function executes in constant time only
    when the two strings have the same length. It short-circuits when they
    have different lengths.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0
