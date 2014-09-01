Basic Signature

libmacaroons:
    
    import macaroons
    m = macaroons.create('http://mybank/', 'this is our super secret key; only we should know it', 'we used our secret key')
    m.signature
    e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f

pymacaroons:

    from macaroons.macaroon import Macaroon
    m = Macaroon(location='http://mybank/', identifier='we used our secret key', key='this is our super secret key; only we should know it')
    m.signature
    e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f


First Party Caveats

libmacaroons:

    import macaroons
    m = macaroons.create('http://mybank/', 'this is our super secret key; only we should know it', 'we used our secret key')
    m = m.add_first_party_caveat('test = caveat')
    m.signature
    '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'

pymacaroons:

    from macaroons.macaroon import Macaroon
    m = Macaroon(location='http://mybank/', identifier='we used our secret key', key='this is our super secret key; only we should know it')
    m.add_first_party_caveat('test = caveat')
    m.signature
    '197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67'


Serializing

libmacaroons:

    import macaroons
    m = macaroons.create('http://mybank/', 'this is our super secret key; only we should know it', 'we used our secret key')
    m = m.add_first_party_caveat('test = caveat')
    m.serialize()
    'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'

pymacaroons:

    from macaroons.macaroon import Macaroon
    m = Macaroon(location='http://mybank/', identifier='we used our secret key', key='this is our super secret key; only we should know it')
    m.add_first_party_caveat('test = caveat')
    m.serialize()
    'MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK'


Deserializing

    from macaroons.macaroon import Macaroon
    m = Macaroon(serialized='MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK')
    print(m.inspect())
    location http://mybank/
    identifier we used our secret key
    cid test = caveat
    signature 197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67


Verifying First Party:

pymacaroons:

    from macaroons.macaroon import Macaroon
    from macaroons.verifier import Verifier
    m = Macaroon(location='http://mybank/', identifier='we used our secret key', key='this is our super secret key; only we should know it')
    m.add_first_party_caveat('test = caveat')

    v = Verifier()
    v.satisfy_exact('test = caveat')
    v.verify(m, 'this is our super secret key; only we should know it')

