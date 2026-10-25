-- Platform "mail" (upstream e7f8a9b0c1d2, its mail parts): the platform
-- value, and the gateway's items (one per grant and message seen, or
-- message sent).

ALTER TABLE access_requests DROP CONSTRAINT access_requests_platform_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_platform_check CHECK (platform IN
    ('github', 'homelab', 'kubernetes', 'a2a', 'google', 'agents',
     'sandbox', 'hostexec', 'mcp', 'models', 'pool', 'mail'));
ALTER TABLE grants DROP CONSTRAINT grants_platform_check;
ALTER TABLE grants ADD CONSTRAINT grants_platform_check CHECK (platform IN
    ('github', 'homelab', 'kubernetes', 'a2a', 'google', 'agents',
     'sandbox', 'hostexec', 'mcp', 'models', 'pool', 'mail'));
ALTER TABLE rules DROP CONSTRAINT rules_platform_check;
ALTER TABLE rules ADD CONSTRAINT rules_platform_check CHECK (platform IN
    ('github', 'homelab', 'kubernetes', 'a2a', 'google', 'agents',
     'sandbox', 'hostexec', 'mcp', 'models', 'pool', 'mail'));

-- A mail grant's address never changes, except once: a grant made by
-- `create` is for the alias it made, so provisioning moves its resource
-- from the domain to the alias. (a2a grants follow their agent's renames.)
CREATE FUNCTION grants_mail_resource_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.platform = 'mail' AND NEW.resource <> OLD.resource AND NOT (
        OLD.status = 'provisioning' AND NEW.status = 'provisioning'
        AND OLD.authority->>'action' = 'create' AND position('@' IN OLD.resource) = 0
        AND right(NEW.resource, length(OLD.resource) + 1) = '@' || OLD.resource
    ) THEN
        RAISE EXCEPTION 'a mail grant''s address is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER grants_mail_resource_guard
    BEFORE UPDATE ON grants
    FOR EACH ROW EXECUTE FUNCTION grants_mail_resource_guard();

CREATE TABLE mail_items (
    id                uuid PRIMARY KEY,
    grant_id          uuid NOT NULL,
    agent_id          uuid NOT NULL REFERENCES agents (id),
    address           text NOT NULL CHECK (length(address) BETWEEN 1 AND 320),
    direction         text NOT NULL CHECK (direction IN ('in', 'out')),
    -- The backend's id of the message (inbound), or "sent:<id>".
    message_key       text CHECK (length(message_key) BETWEEN 1 AND 512),
    thread_key        text CHECK (length(thread_key) BETWEEN 1 AND 512),
    -- What may be shown (subject, from, snippet...), and the fingerprint of
    -- the constraints it was judged under (`fp`).
    summary           jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(summary) = 'object'),
    verdict           text CHECK (length(verdict) <= 16),
    injection         text CHECK (length(injection) <= 16),
    reason            text NOT NULL DEFAULT '' CHECK (length(reason) <= 4000),
    status            text NOT NULL CHECK (status IN
                      ('ignored', 'withheld', 'held', 'error', 'delivered', 'released',
                       'discarded', 'sending', 'sent', 'failed', 'refused')),
    -- A held draft (SecretBox, bound to this row), until it is sent or
    -- discarded.
    payload_encrypted text,
    decided_by        text CHECK (length(decided_by) <= 128),
    decided_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    -- The item is of the grant's own agent.
    CONSTRAINT fk_mail_items_grant FOREIGN KEY (grant_id, agent_id) REFERENCES grants (id, agent_id),
    CONSTRAINT uq_mail_items_grant_message UNIQUE (grant_id, direction, message_key),
    CONSTRAINT mail_items_inbound_key CHECK (direction = 'out' OR message_key IS NOT NULL),
    CONSTRAINT mail_items_statuses CHECK (
        (direction = 'in' AND status IN ('ignored', 'withheld', 'held', 'error', 'delivered',
                                          'released', 'discarded'))
        OR (direction = 'out' AND status IN ('sending', 'held', 'refused', 'sent', 'failed',
                                              'discarded'))
    ),
    CONSTRAINT mail_items_payload CHECK (
        payload_encrypted IS NULL OR (direction = 'out' AND status IN ('held', 'sending'))
    ),
    CONSTRAINT mail_items_decided CHECK ((decided_by IS NULL) = (decided_at IS NULL))
);
CREATE INDEX ix_mail_items_grant_id ON mail_items (grant_id);
CREATE INDEX ix_mail_items_agent_id ON mail_items (agent_id);
CREATE INDEX ix_mail_items_thread_key ON mail_items (thread_key);
CREATE INDEX ix_mail_items_held ON mail_items (created_at) WHERE status = 'held';

-- What may follow what. Inbound: screening may judge an item again while
-- it is not released or discarded; the operator releases or discards a
-- held one. Outbound: held → sending (released) | discarded, sending →
-- sent | failed. Identity never changes.
CREATE FUNCTION mail_items_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.direction = 'out' AND NEW.status NOT IN ('sending', 'held', 'refused') THEN
            RAISE EXCEPTION 'outbound mail item inserted as %', NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.status IN ('released', 'discarded') THEN
            RAISE EXCEPTION 'mail item inserted as %', NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.grant_id <> OLD.grant_id OR NEW.agent_id <> OLD.agent_id
       OR NEW.direction <> OLD.direction OR NEW.address <> OLD.address
       OR NEW.created_at <> OLD.created_at
       OR (OLD.message_key IS NOT NULL AND NEW.message_key IS DISTINCT FROM OLD.message_key) THEN
        RAISE EXCEPTION 'mail item identity columns are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.direction = 'in' AND OLD.status IN ('ignored', 'withheld', 'error', 'delivered', 'held')
            AND NEW.status IN ('ignored', 'withheld', 'held', 'error', 'delivered')) OR
        (OLD.direction = 'in' AND OLD.status = 'held' AND NEW.status IN ('released', 'discarded')) OR
        (OLD.direction = 'out' AND OLD.status = 'held' AND NEW.status IN ('sending', 'discarded')) OR
        (OLD.direction = 'out' AND OLD.status = 'sending' AND NEW.status IN ('sent', 'failed'))
    ) THEN
        RAISE EXCEPTION 'mail item status % -> % is not allowed', OLD.status, NEW.status
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status IN ('released', 'discarded', 'sent', 'failed', 'refused')
       AND (NEW.summary <> OLD.summary OR NEW.verdict IS DISTINCT FROM OLD.verdict
            OR NEW.injection IS DISTINCT FROM OLD.injection) THEN
        RAISE EXCEPTION 'a decided mail item is not judged again'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER mail_items_guard
    BEFORE INSERT OR UPDATE ON mail_items
    FOR EACH ROW EXECUTE FUNCTION mail_items_guard();
