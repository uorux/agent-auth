-- Web UI connectors (surfaces spec §C): an agent bound to an OAuth client
-- is a web connector, and policy keys "always a human" on its runtime
-- being 'web'. Tie the two together here so the runtime cannot be cleared
-- (a panel session may PATCH attributes) and a client binds only to a web
-- agent, once.

CREATE FUNCTION agents_web_connector_runtime() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.runtime IS DISTINCT FROM OLD.runtime
       AND EXISTS (SELECT 1 FROM oauth_clients WHERE agent_id = OLD.id) THEN
        RAISE EXCEPTION 'a web connector''s agent keeps runtime web'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER agents_web_connector_runtime
    BEFORE UPDATE OF runtime ON agents
    FOR EACH ROW EXECUTE FUNCTION agents_web_connector_runtime();

CREATE FUNCTION oauth_clients_web_agent() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.agent_id IS NOT NULL
       AND NEW.agent_id IS DISTINCT FROM OLD.agent_id THEN
        RAISE EXCEPTION 'an OAuth client stays bound to its agent'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.agent_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agents WHERE id = NEW.agent_id AND runtime = 'web'
    ) THEN
        RAISE EXCEPTION 'an OAuth client binds only to a web agent'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER oauth_clients_web_agent
    BEFORE INSERT OR UPDATE OF agent_id ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION oauth_clients_web_agent();

-- Registrations nobody authorized are evicted oldest first.
CREATE INDEX ix_oauth_clients_unbound ON oauth_clients (created_at)
    WHERE agent_id IS NULL AND revoked_at IS NULL;
