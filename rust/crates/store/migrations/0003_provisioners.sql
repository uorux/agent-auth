-- Provisioners (rust/spec/provisioners.md).
--
-- One LLDAP account per agent (B2): two agents sharing an account, or a
-- case variant of one (LLDAP user ids are case-insensitive), would let one
-- agent's grants reset the other's password and share its memberships.
CREATE UNIQUE INDEX uq_agents_lldap_username
    ON agents (lower(lldap_username)) WHERE lldap_username IS NOT NULL;
