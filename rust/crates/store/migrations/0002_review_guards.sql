-- Guards from the security review of the store (rust-port 8f7b4b4).

-- What a request asks for is fixed once it is stored: approvals and
-- clearances are checked against the row's authority, so it must not move
-- under them. (A human's edit goes to approved_resource/approved_authority.)
CREATE FUNCTION access_requests_spec_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.authority IS DISTINCT FROM OLD.authority
       OR NEW.resource <> OLD.resource
       OR NEW.requested_capability <> OLD.requested_capability
       OR NEW.requested_scope <> OLD.requested_scope
       OR NEW.requested_duration_secs <> OLD.requested_duration_secs THEN
        RAISE EXCEPTION 'access request spec columns are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER access_requests_spec_guard
    BEFORE UPDATE ON access_requests
    FOR EACH ROW EXECUTE FUNCTION access_requests_spec_guard();

-- A grant row is the record of a provisioning in progress: its request must
-- be PROVISIONING when it is inserted.
CREATE FUNCTION grants_request_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_requests WHERE id = NEW.request_id AND status = 'provisioning'
    ) THEN
        RAISE EXCEPTION 'grant for a request that is not provisioning'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER grants_request_guard
    BEFORE INSERT ON grants
    FOR EACH ROW EXECUTE FUNCTION grants_request_guard();
