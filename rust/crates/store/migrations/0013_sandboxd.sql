-- Agent VMs (sandboxd spec B-1, B-10): why an agent was disabled, so a
-- renewal of a minted agent never undoes the operator's disable.
--   operator  the admin endpoint or panel (a renewal is refused)
--   lease     its lease (or an ancestor's) ran out (a renewal re-enables
--             it, with a new key)
--   unpaired  its agent VM was unpaired
-- NULL while enabled; NULL on a disabled row means "unknown" and is
-- treated like `operator`.
ALTER TABLE agents
    ADD COLUMN disabled_reason text
        CHECK (disabled_reason IN ('operator', 'lease', 'unpaired')),
    ADD CONSTRAINT agents_disabled_reason CHECK (disabled OR disabled_reason IS NULL);
