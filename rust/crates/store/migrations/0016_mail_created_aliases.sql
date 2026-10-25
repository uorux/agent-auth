-- Final review (mail): an alias the broker created is tied to the agent
-- that created it; anyone else's grant on it is a human's decision.
CREATE TABLE mail_created_aliases (
    address    text PRIMARY KEY CHECK (length(address) BETWEEN 3 AND 320 AND address = lower(address)),
    agent_id   uuid NOT NULL REFERENCES agents (id),
    grant_id   uuid NOT NULL REFERENCES grants (id),
    created_at timestamptz NOT NULL DEFAULT now()
);
