-- Evals: every model decision the broker makes is recorded (what it was
-- built from, the exact prompts, the answer), can be labelled with what
-- it should have been, and can be replayed with another model, system
-- prompt or context setting. Recording never changes a decision.

-- System prompts, once each (calls refer to them by digest).
CREATE TABLE model_prompts (
    sha256     text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    text       text NOT NULL CHECK (length(text) <= 200000),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE model_calls (
    id            uuid PRIMARY KEY,
    kind          text NOT NULL CHECK (kind ~ '^[a-z_]{1,32}$'),
    model         text NOT NULL CHECK (length(model) BETWEEN 1 AND 128),
    -- What the prompt was built from (replays rebuild it from these).
    facts         jsonb NOT NULL CHECK (jsonb_typeof(facts) = 'object'
                                        AND octet_length(facts::text) <= 2000000),
    -- The variant's context settings the prompt was built with.
    context       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(context) = 'object'),
    system_sha256 text NOT NULL REFERENCES model_prompts (sha256),
    user_message  text NOT NULL CHECK (octet_length(user_message) <= 2000000),
    -- The model's object, if it answered one.
    answer        jsonb CHECK (answer IS NULL OR (jsonb_typeof(answer) = 'object'
                                                    AND octet_length(answer::text) <= 2000000)),
    -- The decision class read from the answer (kind-specific; NULL: none).
    class         text CHECK (class IS NULL OR length(class) <= 64),
    error         text CHECK (error IS NULL OR length(error) <= 2000),
    latency_ms    integer NOT NULL CHECK (latency_ms >= 0),
    -- What the call was about: {"request_id": ...}, {"job_id": ...}, ...
    subject       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(subject) = 'object'
                                                     AND octet_length(subject::text) <= 4000),
    created_at    timestamptz NOT NULL
);

CREATE INDEX model_calls_kind_time ON model_calls (kind, created_at DESC, id DESC);
CREATE INDEX model_calls_subject ON model_calls USING gin (subject jsonb_path_ops);

-- What a call should have decided: a class pattern ('*' for any part
-- between '/'), from the operator or from what happened next.
CREATE TABLE model_call_labels (
    call_id    uuid PRIMARY KEY REFERENCES model_calls (id) ON DELETE CASCADE,
    expected   text NOT NULL CHECK (length(expected) BETWEEN 1 AND 64),
    note       text NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
    source     text NOT NULL CHECK (source IN ('operator', 'outcome')),
    labeled_by text NOT NULL CHECK (length(labeled_by) BETWEEN 1 AND 128),
    labeled_at timestamptz NOT NULL
);

-- A replay: recorded calls of one kind, rebuilt and asked again.
CREATE TABLE eval_runs (
    id            uuid PRIMARY KEY,
    kind          text NOT NULL CHECK (kind ~ '^[a-z_]{1,32}$'),
    model         text NOT NULL CHECK (length(model) BETWEEN 1 AND 128),
    system_sha256 text NOT NULL REFERENCES model_prompts (sha256),
    context       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(context) = 'object'),
    selection     jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(selection) = 'object'),
    status        text NOT NULL CHECK (status IN ('running', 'done', 'failed', 'cancelled')),
    total         integer NOT NULL CHECK (total >= 0),
    note          text NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
    created_by    text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at    timestamptz NOT NULL,
    finished_at   timestamptz
);

CREATE TABLE eval_results (
    run_id     uuid NOT NULL REFERENCES eval_runs (id) ON DELETE CASCADE,
    call_id    uuid NOT NULL REFERENCES model_calls (id) ON DELETE CASCADE,
    answer     jsonb CHECK (answer IS NULL OR jsonb_typeof(answer) = 'object'),
    class      text CHECK (class IS NULL OR length(class) <= 64),
    error      text CHECK (error IS NULL OR length(error) <= 2000),
    latency_ms integer NOT NULL CHECK (latency_ms >= 0),
    PRIMARY KEY (run_id, call_id)
);

-- A recorded call is evidence: it never changes (only retention deletes).
CREATE FUNCTION model_calls_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recorded model calls are never changed'
        USING ERRCODE = 'check_violation';
END $$;

CREATE TRIGGER model_calls_guard
    BEFORE UPDATE ON model_calls
    FOR EACH ROW EXECUTE FUNCTION model_calls_guard();

CREATE INDEX model_calls_time ON model_calls (created_at);
