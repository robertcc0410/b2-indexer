-- change request_id type length
-- v1.1.0
ALTER TABLE sinohope ALTER COLUMN request_id TYPE VARCHAR(128);

-- add btc_from_aa_address field
ALTER TABLE deposit_history ADD COLUMN btc_from_evm_address VARCHAR(42) DEFAULT '';

-- Handling withdraw one-to-many transactions
DROP INDEX idx_withdraw_history_b2_tx_hash;
CREATE UNIQUE INDEX idx_unique_b2_tx ON withdraw_history (b2_tx_hash, b2_tx_index, b2_log_index);


