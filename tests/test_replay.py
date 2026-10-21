import stat

import pytest

from keycard_nostr_bunker.replay import COMPACT_SLACK, RETENTION, WINDOW, ReplayWindow

NOW = 1_000_000


def clock(start=NOW):
    time = [start]
    return time, (lambda: time[0])


def lines(path):
    return path.read_text().splitlines() if path.exists() else []


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_fresh_on_both_sides_of_now():
    window = ReplayWindow(now=lambda: NOW)
    assert window.admit('past', NOW - WINDOW, known=True)
    assert window.admit('future', NOW + WINDOW, known=True)
    for created_at in (NOW - WINDOW - 1, NOW + WINDOW + 1):
        with pytest.raises(ValueError, match='window'):
            window.admit('stale', created_at, known=True)


def test_an_event_is_served_once():
    window = ReplayWindow(now=lambda: NOW)
    assert window.admit('a', NOW, known=True) and not window.admit('a', NOW, known=True)
    assert window.admit('s', NOW, known=False) and not window.admit('s', NOW, known=False)
    assert not window.admit('s', NOW, known=True)


def test_since():
    assert ReplayWindow(now=lambda: NOW).since() == NOW - WINDOW


def test_known_ids_survive_a_restart_and_strangers_stay_in_memory(tmp_path):
    path = tmp_path / 'seen'
    window = ReplayWindow(path, now=lambda: NOW)
    window.admit('known', NOW, known=True)
    window.admit('stranger', NOW, known=False)
    assert lines(path) == [f'known {NOW}']
    restarted = ReplayWindow(path, now=lambda: NOW + 1)
    assert not restarted.admit('known', NOW, known=True)
    assert restarted.admit('stranger', NOW, known=False)


def test_ids_are_kept_while_their_request_can_still_be_fresh(tmp_path):
    path = tmp_path / 'seen'
    time, now = clock()
    ReplayWindow(path, now=now).admit('future', NOW + WINDOW, known=True)
    time[0] = NOW + 2 * WINDOW
    assert not ReplayWindow(path, now=now).admit('future', NOW + WINDOW, known=True)


def test_a_flood_of_strangers_cannot_evict_known_ids(tmp_path):
    window = ReplayWindow(tmp_path / 'seen', now=lambda: NOW, limit=5)
    window.admit('known', NOW, known=True)
    for i in range(5000):
        window.admit(f's{i}', NOW, known=False)
    assert not window.admit('known', NOW, known=True)


def test_the_file_tracks_the_live_ids(tmp_path):
    path = tmp_path / 'seen'
    time, now = clock()
    window = ReplayWindow(path, now=now)
    for i in range(3000):
        time[0] += 1
        window.admit(f'id{i}', time[0], known=True)
        assert len(lines(path)) <= 2 * (RETENTION + 1) + COMPACT_SLACK


def test_a_restart_keeps_only_the_newest_ids(tmp_path):
    path = tmp_path / 'seen'
    path.write_text(''.join(f'id{i} {NOW}\n' for i in range(50)))
    window = ReplayWindow(path, now=lambda: NOW, limit=5)
    assert len(lines(path)) == 5
    assert not window.admit('id49', NOW, known=True)
    assert window.admit('id0', NOW, known=True)


def test_expired_ids_leave_the_file_on_restart(tmp_path):
    path = tmp_path / 'seen'
    ReplayWindow(path, now=lambda: NOW).admit('old', NOW, known=True)
    ReplayWindow(path, now=lambda: NOW + RETENTION + 1)
    assert lines(path) == []


def test_the_seen_file_is_private(tmp_path):
    path = tmp_path / 'state' / 'seen'
    ReplayWindow(path, now=lambda: NOW).admit('a', NOW, known=True)
    assert mode(path) == 0o600 and mode(path.parent) == 0o700
