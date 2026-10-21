import pytest

from keycard_nostr_bunker.perms import Permissions


@pytest.mark.parametrize('raw', [None, '', '   ', 5, ['sign_event']])
def test_nothing_requested_is_unrestricted(raw):
    perms = Permissions.requested(raw)
    assert perms.items is None
    assert perms.allows('nip04_decrypt') and perms.allows('sign_event', 30023)


def test_requested_list():
    perms = Permissions.requested(' nip44_encrypt , sign_event:4,sign_event:1059 ,bad item,x:y')
    assert perms.items == {'nip44_encrypt', 'sign_event:4', 'sign_event:1059'}
    assert perms.allows('sign_event', 4) and not perms.allows('sign_event', 1)
    assert perms.allows('nip44_encrypt') and not perms.allows('nip44_decrypt')
    assert perms.allows('ping') and perms.allows('get_public_key')


def test_describe():
    assert 'no permissions requested' in Permissions(None).describe()
    assert Permissions(frozenset()).describe() == 'nothing beyond ping and get_public_key'
    assert Permissions.requested('sign_event:1,nip44_encrypt').describe() == \
        'nip44_encrypt, sign_event:1'
