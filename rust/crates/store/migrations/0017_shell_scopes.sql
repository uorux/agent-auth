-- Scoped shells: inside a shell grant of mode "umbrella" (one host shell,
-- opened with the operator's TOTP code), the agent opens scopes, each with
-- a purpose a model checked against the umbrella's concept. Commands run
-- only in a scope, guarded against its purpose. hostd knows nothing of
-- scopes: they live here, and end with their umbrella.
CREATE TABLE shell_scopes (
    id         uuid PRIMARY KEY,
    grant_id   uuid NOT NULL,
    agent_id   uuid NOT NULL REFERENCES agents (id),
    purpose    text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 4000),
    verdict    text NOT NULL CHECK (length(verdict) <= 2000),
    opened_at  timestamptz NOT NULL,
    closed_at  timestamptz,
    CONSTRAINT fk_shell_scopes_grant
        FOREIGN KEY (grant_id, agent_id) REFERENCES grants (id, agent_id),
    CONSTRAINT shell_scopes_closed_after CHECK (closed_at IS NULL OR closed_at >= opened_at)
);

CREATE INDEX shell_scopes_open ON shell_scopes (grant_id) WHERE closed_at IS NULL;

-- A scope is opened (never already closed) only in an active umbrella
-- shell; afterwards only its closing time may be set, once.
CREATE FUNCTION shell_scopes_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.closed_at IS NOT NULL THEN
            RAISE EXCEPTION 'a shell scope is opened, not inserted closed'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM grants
            WHERE id = NEW.grant_id AND platform = 'hostexec' AND status = 'active'
              AND authority->>'action' = 'shell' AND authority->>'mode' = 'umbrella'
        ) THEN
            RAISE EXCEPTION 'a shell scope needs an active umbrella shell grant'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.grant_id <> OLD.grant_id OR NEW.agent_id <> OLD.agent_id
       OR NEW.purpose <> OLD.purpose OR NEW.verdict <> OLD.verdict
       OR NEW.opened_at <> OLD.opened_at THEN
        RAISE EXCEPTION 'a shell scope changes only by closing'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.closed_at IS NOT NULL AND NEW.closed_at IS DISTINCT FROM OLD.closed_at THEN
        RAISE EXCEPTION 'a closed shell scope stays closed'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER shell_scopes_guard
    BEFORE INSERT OR UPDATE ON shell_scopes
    FOR EACH ROW EXECUTE FUNCTION shell_scopes_guard();

-- Which scope a command ran in. Written with the job, never changed; the
-- job and the scope belong to the same grant, and the scope was open.
CREATE TABLE shell_scope_jobs (
    job_id   uuid PRIMARY KEY REFERENCES host_jobs (id),
    scope_id uuid NOT NULL REFERENCES shell_scopes (id)
);

CREATE INDEX shell_scope_jobs_scope ON shell_scope_jobs (scope_id);

CREATE FUNCTION shell_scope_jobs_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'a command''s scope never changes'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM shell_scopes s JOIN host_jobs j ON j.grant_id = s.grant_id
        WHERE s.id = NEW.scope_id AND j.id = NEW.job_id AND s.closed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'a command runs only in an open scope of its own shell'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER shell_scope_jobs_guard
    BEFORE INSERT OR UPDATE ON shell_scope_jobs
    FOR EACH ROW EXECUTE FUNCTION shell_scope_jobs_guard();
