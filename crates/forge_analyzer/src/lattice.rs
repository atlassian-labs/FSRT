pub trait MeetSemiLattice: Eq {
    fn meet(&mut self, other: Self) -> bool;
}

impl MeetSemiLattice for bool {
    fn meet(&mut self, other: Self) -> bool {
        let prev = *self;
        *self &= other;
        prev != *self
    }
}
