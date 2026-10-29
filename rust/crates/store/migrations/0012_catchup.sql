-- Catching up with upstream's 2026-10 work: platform "pool" (scarce things
-- one agent holds at a time) and its leases.

-- The platforms every table may name. (The mail part adds 'mail' to the
-- same three constraints.)
ALTER TABLE access_requests DROP CONSTRAINT access_requests_platform_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_platform_check CHECK (platform IN
    ('github', 'homelab', 'kubernetes', 'a2a', 'google', 'agents',
     'sandbox', 'hostexec', 'mcp', 'models', 'pool'));
ALTER TABLE grants DROP CONSTRAINT grants_platform_check;
ALTER TABLE grants ADD CONSTRAINT grants_platform_check CHECK (platform IN
    ('github', 'homelab', 'kubernetes', 'a2a', 'google', 'agents',
     'sandbox', 'hostexec', 'mcp', 'models', 'pool'));
ALTER TABLE rules DROP CONSTRAINT rules_platform_check;
ALTER TABLE rules ADD CONSTRAINT rules_platform_check CHECK (platform IN
    ('github', 'homelab', 'kubernetes', 'a2a', 'google', 'agents',
     'sandbox', 'hostexec', 'mcp', 'models', 'pool'));

-- An item of a pool held by a grant. The unique (pool, item, slot) keeps two
-- grants from one slot of an item (capacity), and (pool, agent_id,
-- agent_slot) an agent within the pool's max_per_agent, whatever races. The
-- row goes when the grant ends (the provisioner's revoke).
CREATE TABLE pool_leases (
    id          uuid PRIMARY KEY,
    pool        text NOT NULL CHECK (length(pool) BETWEEN 1 AND 64),
    item        text NOT NULL CHECK (length(item) BETWEEN 1 AND 128),
    slot        integer NOT NULL CHECK (slot >= 0),
    grant_id    uuid NOT NULL,
    agent_id    uuid NOT NULL REFERENCES agents (id),
    agent_slot  integer NOT NULL CHECK (agent_slot >= 0),
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_pool_leases_grant UNIQUE (grant_id),
    CONSTRAINT uq_pool_leases_slot UNIQUE (pool, item, slot),
    CONSTRAINT uq_pool_leases_agent_slot UNIQUE (pool, agent_id, agent_slot),
    CONSTRAINT fk_pool_leases_grant
        FOREIGN KEY (grant_id, agent_id) REFERENCES grants (id, agent_id)
);
CREATE INDEX ix_pool_leases_agent_id ON pool_leases (agent_id);

-- A lease is taken only while its grant is being provisioned, for a pool
-- grant on that very pool; and a lease row never changes.
CREATE FUNCTION pool_leases_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'pool leases are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM grants
        WHERE id = NEW.grant_id AND platform = 'pool' AND resource = NEW.pool
          AND status = 'provisioning'
    ) THEN
        RAISE EXCEPTION 'a pool lease needs a pool grant being provisioned'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER pool_leases_guard
    BEFORE INSERT OR UPDATE ON pool_leases
    FOR EACH ROW EXECUTE FUNCTION pool_leases_guard();
