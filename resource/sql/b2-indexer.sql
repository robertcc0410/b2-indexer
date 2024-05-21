-- change request_id type length
-- v1.1.0
ALTER TABLE sinohope ALTER COLUMN request_id TYPE VARCHAR(128);


-- add btc_from_aa_address field
ALTER TABLE deposit_history ADD COLUMN btc_from_evm_address VARCHAR(42) DEFAULT '';