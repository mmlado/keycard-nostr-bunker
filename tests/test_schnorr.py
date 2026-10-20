"""BIP-340 test vectors (bips/bip-0340/test-vectors.csv)."""

import pytest

from keycard_bunker import schnorr

VECTORS = [
    # seckey, pubkey, aux, msg, sig
    ('0000000000000000000000000000000000000000000000000000000000000003',
     'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
     '0000000000000000000000000000000000000000000000000000000000000000',
     '0000000000000000000000000000000000000000000000000000000000000000',
     'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215'
     '25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0'),
    ('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF',
     'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
     '0000000000000000000000000000000000000000000000000000000000000001',
     '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
     '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341'
     '8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'),
    ('C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9',
     'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8',
     'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906',
     '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
     '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B'
     'AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7'),
    ('0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710',
     '25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517',
     'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
     'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
     '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC'
     '97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3'),
]


@pytest.mark.parametrize('seckey,pubkey,aux,msg,sig', VECTORS)
def test_sign_vectors(seckey, pubkey, aux, msg, sig):
    seckey, pubkey, aux, msg, sig = (bytes.fromhex(v) for v in (seckey, pubkey, aux, msg, sig))
    assert schnorr.pubkey(seckey) == pubkey
    assert schnorr.sign(seckey, msg, aux) == sig
    assert schnorr.verify(pubkey, msg, sig)


def test_verify_rejects_tampered_signature():
    seckey, pubkey, aux, msg, sig = (bytes.fromhex(v) for v in VECTORS[1])
    bad = bytes([sig[0] ^ 1]) + sig[1:]
    assert not schnorr.verify(pubkey, msg, bad)
    assert not schnorr.verify(pubkey, bytes(32), sig)


def test_verify_rejects_pubkey_off_curve():
    _, _, _, msg, sig = (bytes.fromhex(v) for v in VECTORS[1])
    # x = 4 has no square root for y^2 = x^3 + 7
    assert not schnorr.verify((4).to_bytes(32, 'big'), msg, sig)


def test_sign_with_random_aux_verifies():
    seckey = bytes.fromhex(VECTORS[2][0])
    msg = bytes(range(32))
    sig = schnorr.sign(seckey, msg)
    assert schnorr.verify(schnorr.pubkey(seckey), msg, sig)


def test_ecdh_is_symmetric():
    a = bytes.fromhex(VECTORS[1][0])
    b = bytes.fromhex(VECTORS[2][0])
    assert schnorr.ecdh_x(a, schnorr.pubkey(b)) == schnorr.ecdh_x(b, schnorr.pubkey(a))


def test_ecdh_with_generator():
    one = (1).to_bytes(32, 'big')
    g_x = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    assert schnorr.ecdh_x(one, g_x) == g_x


def test_uncompressed_generator():
    g_x = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    g_y = bytes.fromhex('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
    assert schnorr.uncompressed(g_x) == b'\x04' + g_x + g_y


@pytest.mark.parametrize('seckey', [bytes(32), b'\xff' * 32, b'\x01' * 31])
def test_invalid_seckey(seckey):
    with pytest.raises(ValueError):
        schnorr.pubkey(seckey)
