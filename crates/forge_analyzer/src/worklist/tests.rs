use super::WorkList;

#[test]
fn forced_work_is_coalesced_only_while_pending() {
    let mut worklist = WorkList::new();

    worklist.push_back_force(1, 2);
    worklist.push_back_force(1, 2);
    assert_eq!(worklist.len(), 1);

    assert_eq!(worklist.pop_front(), Some((1, 2)));
    worklist.push_back_force(1, 2);
    assert_eq!(worklist.pop_front(), Some((1, 2)));
}
