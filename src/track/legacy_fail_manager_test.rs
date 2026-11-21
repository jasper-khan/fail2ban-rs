use super::*;

fn addr(host: u8) -> IpAddr {
    IpAddr::from([192, 0, 2, host])
}

#[test]
fn interval_boundary_is_strict_and_old_arrival_does_not_move_it() {
    let subject = addr(10);
    let mut manager = LegacyFailManager::new(9, 10);
    assert_eq!(manager.record(subject, 100), 1);
    assert_eq!(manager.record(subject, 110), 2);
    assert_eq!(manager.ticket(subject).unwrap().first_time, 100);
    assert_eq!(manager.record(subject, 111), 3);
    assert_eq!(manager.ticket(subject).unwrap().first_time, 101);
    assert_eq!(manager.record(subject, 80), 4);
    assert_eq!(
        manager.ticket(subject),
        Some(&FailureTicket {
            ip: subject,
            first_time: 101,
            time: 111,
            retry: 4,
            attempts: 4
        })
    );
}

#[test]
fn estimates_retry_rate_using_ties_to_even_not_a_sliding_window() {
    let up = addr(1);
    let down = addr(2);
    let mut manager = LegacyFailManager::new(3, 10);
    // 3 / 20 * 10 = 1.5 -> 2; +1 for the new event.
    assert_eq!(manager.add_failure(up, 100, 3, 0, false), 3);
    assert_eq!(manager.record(up, 120), 3);
    assert_eq!(manager.ticket(up).unwrap().first_time, 110);
    assert_eq!(manager.ticket(up).unwrap().attempts, 2);
    // 5 / 20 * 10 = 2.5 -> 2, not 3.
    assert_eq!(manager.add_failure(down, 100, 5, 0, false), 5);
    assert_eq!(manager.record(down, 120), 3);
}

#[test]
fn retry_weights_attempts_and_global_call_count_are_independent() {
    let a = addr(1);
    let b = addr(2);
    let mut manager = LegacyFailManager::new(5, 10);
    assert_eq!(manager.add_failure(a, 100, 4, 0, false), 4);
    assert_eq!(manager.ticket(a).unwrap().attempts, 1);
    assert_eq!(manager.add_failure(a, 100, 2, 8, false), 6);
    assert_eq!(manager.ticket(a).unwrap().attempts, 9);
    assert_eq!(manager.add_failure(b, 100, 1, 3, true), 3);
    assert!(manager.ticket(b).is_none());
    assert_eq!(manager.total_failures(), 2);
    assert_eq!(manager.add_failure(a, 100, 2, 1, true), 8);
    assert_eq!(manager.ticket(a).unwrap().attempts, 10);
    assert_eq!(manager.total_failures(), 3);
}

#[test]
fn cleanup_expires_at_latest_event_plus_window_not_first_event_plus_window() {
    let mut manager = LegacyFailManager::new(3, 10);
    let a = addr(1);
    manager.record(a, 100);
    manager.record(a, 107);
    manager.record(a, 105);
    assert_eq!(manager.cleanup(110), 0);
    assert_eq!(manager.cleanup(116), 0);
    assert_eq!(manager.cleanup(117), 1);
    assert!(manager.ticket(a).is_none());
    assert_eq!(manager.total_failures(), 3);
}

#[test]
fn threshold_pop_preserves_order_and_only_falls_back_for_absent_id() {
    let mut manager = LegacyFailManager::new(2, 10);
    let a = addr(200);
    let b = addr(50);
    let below = addr(1);
    manager.record(a, 100);
    manager.record(b, 100);
    manager.record(b, 101);
    manager.record(a, 102);
    manager.record(below, 103);
    assert_eq!(manager.take_for_ban(Some(below)), None);
    assert_eq!(manager.take_for_ban(Some(addr(99))).unwrap().ip, a);
    assert!(manager.ticket(a).is_none());
    assert_eq!(manager.take_for_ban(None).unwrap().ip, b);
    assert!(manager.take_for_ban(None).is_none());
    assert_eq!(manager.record(a, 104), 1);
    assert_eq!(manager.total_failures(), 6);
}

#[test]
fn mapped_and_plain_ipv4_are_one_subject() {
    let mut manager = LegacyFailManager::new(2, 10);
    let a = addr(25);
    let mapped = "::ffff:192.0.2.25".parse().unwrap();
    assert_eq!(manager.record(mapped, 100), 1);
    assert_eq!(manager.record(a, 101), 2);
    assert_eq!(manager.take_for_ban(Some(mapped)).unwrap().ip, a);
}
