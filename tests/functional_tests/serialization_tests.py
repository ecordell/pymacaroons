from nose.tools import *
from pymacaroons import Macaroon, Verifier, MACAROON_V1, MACAROON_V2
from pymacaroons.serializers import JsonSerializer


class TestSerializationCompatibility(object):

    def setup(self):
        pass

    def test_from_go_macaroon_json_v2(self):
        # The following macaroon have been generated with
        # https://github.com/go-macaroon/macaroon
        # to test the deserialization.
        json_v1 = '{"caveats":[{"cid":"fp caveat"},{"cid":"tp caveat",' \
                  '"vid":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp_MgxHrfLnfvNuYDo' \
                  'zNKWTlRPPx6VemasWnPpJdAWE6FWmOuFX4sB4-a1oAURDp",' \
                  '"cl":"tp location"}],"location":"my location",' \
                  '"identifier":"my identifier",' \
                  '"signature":"483b3881c9990e5099cb6695da3164daa64da60417b' \
                  'caf9e9dc4c0a9968f6636"}'
        json_v1_discharge = '{"caveats":[],"location":"tp location",' \
                            '"identifier":"tp caveat",' \
                            '"signature":"8506007f69ae3e6a654e0b9769f20dd9da5' \
                            'd2af7860070d6776c15989fb7dea6"}'
        m = Macaroon.deserialize(json_v1, serializer=JsonSerializer())
        discharge = Macaroon.deserialize(json_v1_discharge,
                                         serializer=JsonSerializer())
        assert_macaroon(m, discharge, MACAROON_V1)

        binary_v1 = 'MDAxOWxvY2F0aW9uIG15IGxvY2F0aW9uCjAwMWRpZGVudGlmaWVyIG1' \
                    '5IGlkZW50aWZpZXIKMDAxMmNpZCBmcCBjYXZlYXQKMDAxMmNpZCB0cC' \
                    'BjYXZlYXQKMDA1MXZpZCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACn' \
                    '8yDEet8ud+825gOjM0pZOVE8/HpV6Zqxac+kl0BYToVaY64VfiwHj5r' \
                    'WgBREOkKMDAxM2NsIHRwIGxvY2F0aW9uCjAwMmZzaWduYXR1cmUgSDs' \
                    '4gcmZDlCZy2aV2jFk2qZNpgQXvK+encTAqZaPZjYK'
        binary_v1_discharge = 'MDAxOWxvY2F0aW9uIHRwIGxvY2F0aW9uCjAwMTlpZGVud' \
                              'GlmaWVyIHRwIGNhdmVhdAowMDJmc2lnbmF0dXJlIIUGAH' \
                              '9prj5qZU4Ll2nyDdnaXSr3hgBw1ndsFZift96mCg'
        m = Macaroon.deserialize(binary_v1)
        discharge = Macaroon.deserialize(binary_v1_discharge)
        assert_macaroon(m, discharge, MACAROON_V1)

        json_v2 = '{"c":[{"i":"fp caveat"},{"i":"tp caveat",' \
                  '"v64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp_MgxHrfLnfvNuYDoz' \
                  'NKWTlRPPx6VemasWnPpJdAWE6FWmOuFX4sB4-a1oAURDp",' \
                  '"l":"tp location"}],"l":"my location","i":"my identifier",' \
                  '"s64":"SDs4gcmZDlCZy2aV2jFk2qZNpgQXvK-encTAqZaPZjY"}'
        json_v2_discharge = '{"l":"tp location","i":"tp caveat","s64":"hQYAf2' \
                            'muPmplTguXafIN2dpdKveGAHDWd2wVmJ-33qY"}'
        m = Macaroon.deserialize(json_v2, serializer=JsonSerializer())
        discharge = Macaroon.deserialize(json_v2_discharge,
                                         serializer=JsonSerializer())
        assert_macaroon(m, discharge, MACAROON_V2)

        binary_v2 = 'AgELbXkgbG9jYXRpb24CDW15IGlkZW50aWZpZXIAAglmcCBjYXZlYXQ' \
                    'AAQt0cCBsb2NhdGlvbgIJdHAgY2F2ZWF0BEgAAAAAAAAAAAAAAAAAAA' \
                    'AAAAAAAAAAAAACn8yDEet8ud+825gOjM0pZOVE8/HpV6Zqxac+kl0BY' \
                    'ToVaY64VfiwHj5rWgBREOkAAAYgSDs4gcmZDlCZy2aV2jFk2qZNpgQX' \
                    'vK+encTAqZaPZjY'
        binary_v2_discharge = 'AgELdHAgbG9jYXRpb24CCXRwIGNhdmVhdAAABiCFBgB/a' \
                              'a4+amVOC5dp8g3Z2l0q94YAcNZ3bBWYn7fepg'
        m = Macaroon.deserialize(binary_v2)
        discharge = Macaroon.deserialize(binary_v2_discharge)
        assert_macaroon(m, discharge, MACAROON_V2)


def assert_macaroon(m, discharge, version):
    assert_equal(m.location, 'my location')
    assert_equal(m.version, version)
    assert_equal(m.identifier_bytes, b'my identifier')
    v = Verifier()
    v.satisfy_exact('fp caveat')
    verified = v.verify(
        m,
        "my secret key",
        discharge_macaroons=[discharge],
    )
    assert_true(verified)
