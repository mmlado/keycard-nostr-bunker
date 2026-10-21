"""Client admission, tested through its own interface; two instances on one
state directory stand in for the bunker and the CLI."""

import fcntl
import os
import stat
import threading

import pytest

from keycard_nostr_bunker.admission import (CONFIG, PENDING_LIMIT, Admission, AdmissionError,
                                            ClientRecord, defer)
from keycard_nostr_bunker.perms import Permissions
from keycard_nostr_bunker.state import StateDir

A, B, C = ('a' * 64), ('b' * 64), ('c' * 64)
SECRET = 's3cret'
RELAY = 'wss://relay.example'


def memory(**kwargs):
    kwargs.setdefault('secret', SECRET)
    return Admission(None, **kwargs)


def refused(message, call, *args):
    with pytest.raises(AdmissionError) as e:
        call(*args)
    assert str(e.value) == message or message in str(e.value), str(e.value)


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


# records

@pytest.mark.parametrize('line,since,via,items', [
    (f'{A} 1700000000 {RELAY} perms=nip44_encrypt,sign_event:1', 1700000000, RELAY,
     {'nip44_encrypt', 'sign_event:1'}),
    (f'{A} 1700000000 {RELAY}', 1700000000, RELAY, None),
    (f'{A} 1700000000 approved', 1700000000, 'approved', None),
    (f'{A} 1700000000 perms=', 1700000000, '', set()),
    (A, None, '', None),
])
def test_record_round_trip(line, since, via, items):
    record = ClientRecord.parse(line)
    assert record is not None
    assert (record.pubkey, record.since, record.via) == (A, since, via)
    assert record.perms.items == (None if items is None else frozenset(items))
    assert ClientRecord.parse(record.line()) == record


def test_blank_record_line():
    assert ClientRecord.parse('   ') is None


# the secret

def test_secret_is_required_and_a_fixed_one_cannot_rotate():
    with pytest.raises(ValueError):
        Admission(None)
    with pytest.raises(ValueError):
        Admission(None, secret='x', rotate=True)
    assert memory().secret == SECRET


def test_secret_file_is_generated_private_and_shared(tmp_path):
    bunker, cli = Admission(StateDir(tmp_path)), Admission(StateDir(tmp_path))
    first = bunker.secret
    assert len(first) >= 16 and mode(tmp_path / 'secret') == 0o600
    assert cli.secret == first
    (tmp_path / 'secret').unlink()
    assert bunker.secret not in ('', first)


# connect with the secret

def test_connect_with_the_secret_admits():
    adm = memory(now=lambda: 1700000000)
    refused('unauthorized', adm.require, A, 'ping')
    assert adm.connect(A, SECRET, '', RELAY) == 'ack'
    assert adm.admitted(A)
    [record] = adm.clients()
    assert (record.pubkey, record.since, record.via, record.perms) == (
        A, 1700000000, RELAY, Permissions(None))
    adm.require(A, 'sign_event', 3)


def test_wrong_or_missing_secret_is_refused():
    adm = memory()
    refused('invalid secret', adm.connect, A, 'wrong', '', RELAY)
    refused('invalid secret', adm.connect, A, '', '', RELAY)
    assert not adm.admitted(A) and adm.clients() == []


def test_admitted_client_reconnects_without_the_secret():
    adm = memory()
    adm.connect(A, SECRET, '', RELAY)
    assert adm.connect(A, '', '', RELAY) == 'ack'


def test_admitted_clients_survive_a_restart(tmp_path):
    first = Admission(StateDir(tmp_path))
    first.connect(A, first.secret, 'sign_event:1', RELAY)
    second = Admission(StateDir(tmp_path))
    assert second.admitted(A)
    refused('sign_event for kind 3', second.require, A, 'sign_event', 3)


# requested permissions

def test_requested_permissions_are_enforced():
    adm = memory()
    adm.connect(A, SECRET, 'sign_event:1,nip44_encrypt', RELAY)
    adm.require(A, 'sign_event', 1)
    adm.require(A, 'nip44_encrypt')
    adm.require(A, 'ping')
    adm.require(A, 'get_public_key')
    refused('sign_event for kind 3 is not among the permissions this client requested',
            adm.require, A, 'sign_event', 3)
    refused('nip44_decrypt is not among the permissions this client requested',
            adm.require, A, 'nip44_decrypt')


def test_permission_edge_cases():
    adm = memory()
    adm.connect(A, SECRET, '', RELAY)
    adm.connect(B, SECRET, '!!, sign event', RELAY)
    adm.connect(C, SECRET, 'sign_event', RELAY)
    adm.require(A, 'nip04_decrypt')
    refused('not among the permissions', adm.require, B, 'sign_event', 1)
    adm.require(B, 'ping')
    adm.require(C, 'sign_event', 30023)


def test_reconnecting_cannot_widen_permissions():
    adm = memory()
    adm.connect(A, SECRET, 'sign_event:1', RELAY)
    assert adm.connect(A, SECRET, 'sign_event', RELAY) == 'ack'
    refused('not among the permissions', adm.require, A, 'sign_event', 3)


# clients from the config

def test_config_clients_need_no_secret_and_are_unrestricted():
    adm = memory(authorized=[B])
    assert adm.connect(B, '', '', RELAY) == 'ack'
    adm.require(B, 'nip04_decrypt')
    assert [(r.pubkey, r.via) for r in adm.clients()] == [(B, CONFIG)]
    refused('already admitted by connection.authorized_clients', adm.approve, B)


def test_revoking_a_key_in_both_config_and_file_clears_the_file(tmp_path):
    old = Admission(StateDir(tmp_path))
    old.connect(A, old.secret, '', RELAY)
    cli = Admission(StateDir(tmp_path), authorized=[A])
    result = cli.revoke(A)
    assert result.removed and result.in_config and result.rotated
    assert cli.admitted(A)
    after_restart = Admission(StateDir(tmp_path))
    assert not after_restart.admitted(A)


# approval

def test_approver_decides_and_sees_the_request():
    asked = []

    def approver(client, perms):
        asked.append((client, perms.describe()))
        return client == A

    adm = memory(approver=approver)
    assert adm.connect(A, SECRET, 'sign_event:1', RELAY) == 'ack'
    refused('connection refused', adm.connect, B, SECRET, '', RELAY)
    assert asked == [(A, 'sign_event:1'), (B, 'everything, no permissions requested')]
    assert adm.admitted(A) and not adm.admitted(B) and adm.pending() == []


def test_approver_is_not_asked_without_the_secret():
    adm = memory(approver=lambda client, perms: pytest.fail('asked'))
    refused('invalid secret', adm.connect, A, 'wrong', '', RELAY)


def test_deferred_client_waits_and_is_approved_from_the_cli(tmp_path):
    bunker = Admission(StateDir(tmp_path), approver=defer)
    refused('pending approval', bunker.connect, A, bunker.secret, 'sign_event:1', RELAY)
    assert not bunker.admitted(A)
    [waiting] = Admission(StateDir(tmp_path)).pending()
    assert (waiting.pubkey, waiting.via) == (A, RELAY)
    assert waiting.perms.items == frozenset({'sign_event:1'})
    approved = Admission(StateDir(tmp_path)).approve(A)
    assert approved.perms.items == frozenset({'sign_event:1'})
    assert bunker.admitted(A) and bunker.pending() == []
    refused('sign_event for kind 3', bunker.require, A, 'sign_event', 3)


def test_retry_while_pending_is_not_asked_for_a_rotated_secret(tmp_path):
    rotations = []
    bunker = Admission(StateDir(tmp_path), rotate=True, approver=defer,
                       on_rotate=lambda: rotations.append(1))
    url_secret = bunker.secret
    refused('pending approval', bunker.connect, A, url_secret, 'sign_event:1', RELAY)
    assert bunker.secret != url_secret and rotations == [1]
    refused('pending approval', bunker.connect, A, url_secret, 'sign_event:1', RELAY)
    Admission(StateDir(tmp_path)).approve(A)
    assert bunker.connect(A, url_secret, '', RELAY) == 'ack'
    assert rotations == [1]


def test_approve_refuses_anything_not_waiting(tmp_path):
    adm = Admission(StateDir(tmp_path))
    refused('is not waiting for approval', adm.approve, A)
    adm.connect(B, adm.secret, '', RELAY)
    refused('is already admitted', adm.approve, B)
    assert not adm.admitted(A)


def test_a_client_pushed_out_of_pending_cannot_be_approved_unrestricted(tmp_path):
    bunker = Admission(StateDir(tmp_path), approver=defer)
    secret = bunker.secret
    first = f'{0:064x}'
    refused('pending approval', bunker.connect, first, secret, 'sign_event:1', RELAY)
    for i in range(1, PENDING_LIMIT + 1):
        refused('pending approval', bunker.connect, f'{i:064x}', secret, '', RELAY)
    assert first not in {r.pubkey for r in bunker.pending()}
    refused('is not waiting for approval', Admission(StateDir(tmp_path)).approve, first)
    assert not bunker.admitted(first)


def test_a_busy_or_deferring_approver_keeps_the_client_pending():
    adm = memory(approver=lambda client, perms: None)
    refused('pending approval', adm.connect, A, SECRET, '', RELAY)
    refused('pending approval', adm.connect, A, '', '', RELAY)
    assert [r.pubkey for r in adm.pending()] == [A]


# one URL, one client

def test_rotation_lets_one_url_admit_one_client(tmp_path):
    adm = Admission(StateDir(tmp_path), rotate=True)
    secret = adm.secret
    assert adm.connect(A, secret, '', RELAY) == 'ack'
    refused('invalid secret', adm.connect, B, secret, '', RELAY)


def test_concurrent_connects_with_one_url_admit_one_client(tmp_path):
    adm = Admission(StateDir(tmp_path), rotate=True)
    secret = adm.secret
    barrier = threading.Barrier(8)
    results = []

    def connect(client):
        barrier.wait()
        try:
            results.append(adm.connect(client, secret, '', RELAY))
        except AdmissionError as e:
            results.append(str(e))

    threads = [threading.Thread(target=connect, args=(f'{i:064x}',)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ['ack'] + ['invalid secret'] * 7
    assert len(adm.clients()) == 1


# revoking

def test_revoke_removes_and_rotates(tmp_path):
    adm = Admission(StateDir(tmp_path))
    secret = adm.secret
    adm.connect(A, secret, '', RELAY)
    result = adm.revoke(A)
    assert result.removed and result.rotated and not result.in_config
    assert not adm.admitted(A) and adm.secret != secret
    refused('invalid secret', adm.connect, A, secret, '', RELAY)


def test_revoke_drops_a_pending_request_and_rotates(tmp_path):
    adm = Admission(StateDir(tmp_path), approver=defer)
    secret = adm.secret
    refused('pending approval', adm.connect, A, secret, '', RELAY)
    result = adm.revoke(A)
    assert result.dropped_pending and result.rotated and adm.pending() == []


def test_revoke_with_a_fixed_secret_says_it_cannot_rotate():
    adm = memory()
    adm.connect(A, SECRET, '', RELAY)
    result = adm.revoke(A)
    assert result.removed and not result.rotated and result.secret_fixed


def test_revoke_of_a_stranger_changes_nothing(tmp_path):
    adm = Admission(StateDir(tmp_path))
    secret = adm.secret
    result = adm.revoke(A)
    assert not (result.removed or result.dropped_pending or result.in_config or result.rotated)
    assert adm.secret == secret


# the bunker and the CLI share the state directory

def test_cli_changes_reach_the_bunker_at_once(tmp_path):
    bunker, cli = Admission(StateDir(tmp_path)), Admission(StateDir(tmp_path))
    for _ in range(20):
        bunker.connect(A, bunker.secret, '', RELAY)
        assert bunker.admitted(A)
        cli.revoke(A)
        assert not bunker.admitted(A)


def test_state_files_are_private(tmp_path):
    state = tmp_path / 'state'
    adm = Admission(StateDir(state), approver=defer)
    refused('pending approval', adm.connect, A, adm.secret, '', RELAY)
    adm.approve(A)
    assert mode(state) == 0o700
    for name in ('secret', 'clients', 'pending', 'admission.lock'):
        assert mode(state / name) == 0o600, name


def test_changes_wait_for_the_lock_file(tmp_path):
    adm = Admission(StateDir(tmp_path), approver=defer)
    refused('pending approval', adm.connect, A, adm.secret, '', RELAY)
    fd = os.open(tmp_path / 'admission.lock', os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    done = threading.Event()
    worker = threading.Thread(target=lambda: (adm.approve(A), done.set()))
    worker.start()
    try:
        assert not done.wait(0.3)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    assert done.wait(5)
    worker.join()
    assert adm.admitted(A)
