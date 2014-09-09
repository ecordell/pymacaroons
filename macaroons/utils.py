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
