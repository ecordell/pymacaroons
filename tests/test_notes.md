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


Verifying First Party Exact Caveats:

pymacaroons:

    from macaroons.macaroon import Macaroon
    from macaroons.verifier import Verifier
    m = Macaroon(location='http://mybank/', identifier='we used our secret key', key='this is our super secret key; only we should know it')
    m.add_first_party_caveat('test = caveat')

    v = Verifier()
    v.satisfy_exact('test = caveat')
    v.verify(m, 'this is our super secret key; only we should know it')

Verifying First Party General Caveats:

pymacaroons:

    from macaroons.macaroon import Macaroon
    from macaroons.verifier import Verifier

    m = Macaroon(location='http://mybank/', identifier='we used our secret key', key='this is our super secret key; only we should know it')
    m.add_first_party_caveat('general caveat')

    def general_caveat_validator(predicate):
        return predicate == 'general caveat'

    v = Verifier()
    v.satisfy_general(general_caveat_validator)
    v.verify(m, 'this is our super secret key; only we should know it')



Adding Third Party Caveats:
    
    from macaroons.macaroon import Macaroon
    m = Macaroon(location='http://mybank/', identifier='we used our other secret key', key='this is a different super-secret key; never use the same secret twice')
    m.add_first_party_caveat('account = 3735928559')
    m.serialize()
    caveat_key = '4; guaranteed random by a fair toss of the dice'
    predicate = 'user = Alice'
    identifier = 'this was how we remind auth of key/pred'
    m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)
    print(m.inspect())
    serialized = m.serialize()

    n = Macaroon(serialized=serialized)
    print(n.inspect())


Preparing For Request:

    from macaroons.macaroon import Macaroon
    m = Macaroon(location='http://mybank/', identifier='we used our other secret key', key='this is a different super-secret key; never use the same secret twice')
    m.add_first_party_caveat('account = 3735928559')
    caveat_key = '4; guaranteed random by a fair toss of the dice'
    predicate = 'user = Alice'
    identifier = 'this was how we remind auth of key/pred'
    m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)

    discharge = Macaroon(location='http://auth.mybank/', key=caveat_key, identifier=identifier)
    discharge.add_first_party_caveat('time < 2015-01-01T00:00')
    discharge.signature
    '82a80681f9f32d419af12f6a71787a1bac3ab199df934ed950ddf20c25ac8c65'
    protected = m.prepare_for_request(discharge)
    protected.signature
    'd558b750d42ed3021b8ee092f6ff5882c5084bba059f3d622c8da8eea4d2d1e8'

Verifying Third Party Caveats:

    from macaroons.macaroon import Macaroon
    from macaroons.verifier import Verifier
    m = Macaroon(location='http://mybank/', identifier='we used our other secret key', key='this is a different super-secret key; never use the same secret twice')
    m.add_first_party_caveat('account = 3735928559')
    caveat_key = '4; guaranteed random by a fair toss of the dice'
    predicate = 'user = Alice'
    identifier = 'this was how we remind auth of key/pred'
    m.add_third_party_caveat('http://auth.mybank/', caveat_key, identifier)

    discharge = Macaroon(location='http://auth.mybank/', key=caveat_key, identifier=identifier)
    discharge.add_first_party_caveat('time < 2015-01-01T00:00')
    protected = m.prepare_for_request(discharge)

    v = Verifier()
    v.satisfy_exact('account = 3735928559')
    v.satisfy_exact('time < 2015-01-01T00:00')
    v.verify(m, 'this is a different super-secret key; never use the same secret twice', discharge_macaroons=[protected])


Print types:

    from macaroons.macaroon import Macaroon
    m = Macaroon(location='http://mybank/', identifier='we used our secret key', key='this is our super secret key; only we should know it')
    print(type(m.location))
    print(m.location)
    print(type(m.identifier))
    print(m.identifier)
    print(type(m.signature))
    print(m.signature)

    m.add_first_party_caveat('test = caveat')
    print(type(m.signature))
    print(m.signature)

    create_initial = m._create_initial_macaroon_signature()
    print(type(create_initial))
    print(create_initial)

    mac = m._macaroon_hmac(b'asdfd', 'asdfdf')
    print(type(mac))
    print(mac)

    p = m._packetize('identifier', 'we used our secret key')
    print(type(p))
    print(p)
