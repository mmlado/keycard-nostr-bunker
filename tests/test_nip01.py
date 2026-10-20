from keycard_bunker import nip01, schnorr

PUBKEY = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
SECKEY = (1).to_bytes(32, 'big')


def test_serialization_is_canonical():
    data = nip01.serialize(PUBKEY, 1700000000, 1, [['p', 'ab'], ['t', 'x']], 'héllo "q"\n')
    expected = f'[0,"{PUBKEY}",1700000000,1,[["p","ab"],["t","x"]],"héllo \\"q\\"\\n"]'
    assert data == expected.encode()


def test_event_id_is_deterministic():
    a = nip01.event_id(PUBKEY, 1700000000, 1, [], 'hello')
    b = nip01.event_id(PUBKEY, 1700000000, 1, [], 'hello')
    assert a == b and len(a) == 32
    assert nip01.event_id(PUBKEY, 1700000000, 1, [], 'world') != a
    assert nip01.event_id(PUBKEY, 1700000000, 0, [], 'hello') != a


def test_finalize_event_signs_and_fills_defaults():
    event = nip01.finalize_event({'kind': 1, 'content': 'test'}, PUBKEY,
                                 lambda digest: schnorr.sign(SECKEY, digest))
    assert event['pubkey'] == PUBKEY
    assert event['tags'] == []
    assert event['created_at'] > 1700000000
    expected = nip01.event_id(PUBKEY, event['created_at'], 1, [], 'test')
    assert event['id'] == expected.hex()
    assert schnorr.verify(bytes.fromhex(PUBKEY), expected, bytes.fromhex(event['sig']))


def test_finalize_event_keeps_created_at():
    event = nip01.finalize_event({'kind': 1, 'content': '', 'created_at': 1700000000}, PUBKEY,
                                 lambda digest: bytes(64))
    assert event['created_at'] == 1700000000
