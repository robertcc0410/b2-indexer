-- change request_id type length
ALTER TABLE sinohope ALTER COLUMN request_id TYPE VARCHAR(128);

-- Handling withdraw one-to-many transactions
DROP INDEX idx_withdraw_history_b2_tx_hash;
DROP INDEX idx_withdraw_history_uuid;
CREATE UNIQUE INDEX idx_unique_b2_tx ON withdraw_history (b2_tx_hash, b2_tx_index, b2_log_index);
