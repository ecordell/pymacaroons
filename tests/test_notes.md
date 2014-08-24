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
