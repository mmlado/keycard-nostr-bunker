import pytest

from keycard_nostr_bunker.perms import Permissions


@pytest.mark.parametrize('raw', [None, '', '   ', 5, ['sign_event']])
def test_no_list(raw):
    assert Permissions.requested(raw).items is None


def test_requested_list():
    perms = Permissions.requested(' nip44_encrypt , sign_event:4,sign_event:1059 ,bad item,x:y')
    assert perms.items == {'nip44_encrypt', 'sign_event:4', 'sign_event:1059'}


def test_describe():
    assert Permissions(None).describe() == 'nothing listed'
    assert Permissions(frozenset()).describe() == 'nothing listed'
    assert Permissions.requested('sign_event:1,nip44_encrypt').describe() == \
        'nip44_encrypt, sign_event:1'
