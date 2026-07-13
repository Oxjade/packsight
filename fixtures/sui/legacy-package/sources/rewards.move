module 0xabc::rewards {
    struct Rewards has key {
        id: UID,
        version: u64,
        balance: u64
    }

    /// Deprecated legacy claim path retained for compatibility.
    public entry fun claim_legacy(rewards: &mut Rewards, amount: u64) {
        rewards.balance = rewards.balance - amount;
    }

    public entry fun claim_current(rewards: &mut Rewards, amount: u64) {
        assert!(rewards.version == 2, 0);
        rewards.balance = rewards.balance - amount;
    }
}
