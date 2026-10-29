-- Security review #4 (mail): a held message is released only once its
-- whole text was made available to the operator (`shown_at`), so held
-- inbound items carry their text too (sealed, until decided).

ALTER TABLE mail_items ADD COLUMN shown_at timestamptz;

ALTER TABLE mail_items DROP CONSTRAINT mail_items_payload;
ALTER TABLE mail_items ADD CONSTRAINT mail_items_payload CHECK (
    payload_encrypted IS NULL
    OR (direction = 'out' AND status IN ('held', 'sending'))
    OR (direction = 'in' AND status = 'held')
);
