from macaroons.macaroon import Macaroon


def test():
    m = Macaroon(
        location='http://mybank/',
        identifier='we used our secret key',
        key='this is our super secret key; only we should know it'
    )
    m.signature


if __name__ == '__main__':
    import timeit
    print(timeit.timeit(
        "test()",
        setup="from __main__ import test",
        number=1000000
    ))
