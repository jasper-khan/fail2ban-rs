use super::*;

const LINE_DATE: &str = "Jan  7 03:04:05";
const EVENT_TIME: i64 = 1_767_755_045;
const IP: &str = "192.0.2.10";
const CONN: &str = "Connection from 192.0.2.10 port 55010 on 192.0.2.55 port 22";
const LOCKED: &str = "User example not allowed because account is locked";
const TOO_MANY: &str = "Disconnecting: Too many authentication failures for example [preauth]";
const DIRECT: &str = "Failed password for example from 192.0.2.10 port 55010 ssh2";
const ACCEPTED: &str = "Accepted password for example from 192.0.2.10 port 55010 ssh2";
const OTHER_ACCEPTED: &str = "Accepted password for alternate from 192.0.2.10 port 55010 ssh2";
const DISCONNECT: &str = "Received disconnect from 192.0.2.10 port 55010:11: disconnected by user";
const AUTH_DISCONNECT: &str =
    "Received disconnect from 192.0.2.10 port 55010:3: example: Auth fail";

fn event(state: &mut LegacySshSessions, source: &str, body: &str, wall: i64) -> Option<SshFailure> {
    state.evaluate(&format!("{LINE_DATE} {source}: {body}"), 2026, wall)
}

fn failure(user: &str) -> SshFailure {
    SshFailure {
        ip: IP.parse().unwrap(),
        timestamp: EVENT_TIME,
        user: Some(user.to_owned()),
    }
}

#[test]
fn only_exact_date_stripped_prefix_shares_session_context() {
    let mut state = LegacySshSessions::new();
    assert_eq!(event(&mut state, "lab sshd[41]", CONN, 0), None);
    for other in [
        "other sshd[41]",
        "lab sshd[42]",
        "lab sshd-session[41]",
        "lab  sshd[41]",
        "lab sshd[041]",
    ] {
        assert_eq!(event(&mut state, other, LOCKED, 1), None);
    }
    assert_eq!(
        event(&mut state, "lab sshd[41]", LOCKED, 2),
        Some(failure("example"))
    );
    assert_eq!(
        event(&mut state, "lab sshd[41]", TOO_MANY, 3),
        Some(failure("example"))
    );
}

#[test]
fn pending_is_released_on_context_and_retained_for_later_failures() {
    let mut state = LegacySshSessions::new();
    let source = "lab sshd[41]";
    assert_eq!(event(&mut state, source, LOCKED, 0), None);
    assert_eq!(event(&mut state, source, CONN, 1), Some(failure("example")));
    assert_eq!(
        event(&mut state, source, TOO_MANY, 2),
        Some(failure("example"))
    );
}

#[test]
fn successful_auth_resets_pending_and_keeps_original_multi_user_override() {
    let source = "lab sshd[41]";
    let mut same_user = LegacySshSessions::new();
    assert_eq!(event(&mut same_user, source, LOCKED, 0), None);
    assert_eq!(event(&mut same_user, source, ACCEPTED, 1), None);
    assert_eq!(event(&mut same_user, source, TOO_MANY, 2), None);

    let mut different_user = LegacySshSessions::new();
    assert_eq!(
        event(&mut different_user, source, DIRECT, 0),
        Some(failure("example"))
    );
    assert_eq!(
        event(&mut different_user, source, OTHER_ACCEPTED, 1),
        Some(failure("alternate"))
    );
    assert_eq!(event(&mut different_user, source, TOO_MANY, 2), None);
}

#[test]
fn disconnect_can_release_pending_or_fail_directly_and_always_forgets() {
    let source = "lab sshd[41]";
    let mut state = LegacySshSessions::new();
    assert_eq!(event(&mut state, source, LOCKED, 0), None);
    assert_eq!(
        event(&mut state, source, DISCONNECT, 1),
        Some(failure("example"))
    );
    assert_eq!(event(&mut state, source, LOCKED, 2), None);
    assert_eq!(event(&mut state, source, CONN, 3), Some(failure("example")));
    assert_eq!(
        event(&mut state, source, AUTH_DISCONNECT, 4),
        Some(failure("example"))
    );
    assert_eq!(event(&mut state, source, TOO_MANY, 5), None);
}

#[test]
fn expiry_uses_observation_time_and_hits_do_not_refresh_it() {
    let mut state = LegacySshSessions::new();
    let source = "lab sshd[41]";
    assert_eq!(event(&mut state, source, CONN, 1_000), None);
    assert_eq!(
        event(&mut state, source, LOCKED, 1_299),
        Some(failure("example"))
    );
    assert_eq!(event(&mut state, source, LOCKED, 1_300), None);
}

#[test]
fn cache_evicts_oldest_insertion_not_recent_match_and_limits_input() {
    let mut state = LegacySshSessions::new();
    let original = "lab sshd[1]";
    assert_eq!(event(&mut state, original, CONN, 0), None);
    for pid in 2..=MAX_SESSIONS {
        assert_eq!(
            event(&mut state, &format!("lab sshd[{pid}]"), CONN, 0),
            None
        );
    }
    assert_eq!(
        event(&mut state, original, LOCKED, 1),
        Some(failure("example"))
    );
    assert_eq!(event(&mut state, "lab sshd[101]", CONN, 2), None);
    assert_eq!(state.sessions.len(), MAX_SESSIONS);
    assert_eq!(event(&mut state, original, LOCKED, 3), None);
    assert_eq!(
        event(&mut state, "lab sshd[101]", LOCKED, 4),
        Some(failure("example"))
    );

    let prior = state.sessions.len();
    let huge = format!("{}{CONN}", " ".repeat(MAX_LINE_LEN));
    assert_eq!(event(&mut state, "lab sshd[102]", &huge, 5), None);
    assert!(!state.sessions.iter().any(|s| s.key.contains("[102]")));
    assert_eq!(state.sessions.len(), prior);
}
