-- The gateway connects to servers by address (CC-249): how it trusts the connection, what it last saw of the server and the connection that
-- waits for an administrator are data of the server row. A server that exists before this migration has no approved connection, so its
-- tools wait until an administrator approves one (the gateway proposes it at its first check).
ALTER TABLE servers DROP CONSTRAINT servers_internal_url_check;
ALTER TABLE servers ADD CONSTRAINT servers_internal_url_check CHECK (internal_url ~ '^https?://' AND char_length(internal_url) <= 255);
ALTER TABLE servers ADD COLUMN allow_plain_http boolean NOT NULL DEFAULT false;
ALTER TABLE servers ADD COLUMN status text NOT NULL DEFAULT 'pending_approval'
    CHECK (status IN ('pending_approval', 'connected', 'unreachable', 'certificate_changed', 'manifest_invalid'));
ALTER TABLE servers ADD COLUMN last_checked_at timestamptz;
ALTER TABLE servers ADD COLUMN last_error text CHECK (last_error IS NULL OR last_error ~ '^[a-z][a-z0-9_]*$');
ALTER TABLE servers ADD COLUMN connection jsonb;
ALTER TABLE servers ADD COLUMN pending_connection jsonb;

-- A pulled manifest is the only source of definitions: the value that said "a reviewed commit registered it" is now "manifest".
ALTER TABLE registry_tools DROP CONSTRAINT registry_tools_pending_source_check;
UPDATE registry_tools SET pending_source = 'manifest' WHERE pending_source = 'ci';
ALTER TABLE registry_tools ADD CONSTRAINT registry_tools_pending_source_check CHECK (pending_source IN ('manifest', 'server', 'adapter'));

ALTER TABLE registry_policies DROP CONSTRAINT registry_policies_pending_source_check;
UPDATE registry_policies SET pending_source = 'manifest' WHERE pending_source = 'ci';
ALTER TABLE registry_policies ADD CONSTRAINT registry_policies_pending_source_check CHECK (pending_source IN ('manifest', 'server'));

ALTER TABLE registry_servers DROP CONSTRAINT registry_servers_source_check;
UPDATE registry_servers SET source = 'manifest' WHERE source IN ('ci', 'bootstrap');
ALTER TABLE registry_servers ADD CONSTRAINT registry_servers_source_check CHECK (source IN ('manifest', 'adapter'));

-- The instances that are already running read the registry again when this counter moves.
UPDATE registry_changes SET version = version + 1 WHERE id = 1;
