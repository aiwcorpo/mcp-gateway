-- Servers, scope mapping and emergency overrides are runtime data (2.0.0), changed through the admin API and read again by every
-- instance when registry_changes moves. Nothing of the 1.x static configuration is copied here: it lived in environment variables
-- (MCP_SERVER_*), which this migration cannot see; an administrator adds the servers with POST /admin/v1/servers. The manifests and
-- approvals already stored under the same serverId stay and are taken again when the server is added.

-- A system id is [a-z][a-z0-9]{1,30} since contracts 7.0.0 (it was five fixed names).
ALTER TABLE registry_servers DROP CONSTRAINT registry_servers_server_id_check;
ALTER TABLE registry_servers ADD CONSTRAINT registry_servers_server_id_check CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$');
ALTER TABLE registry_tools DROP CONSTRAINT registry_tools_server_id_check;
ALTER TABLE registry_tools ADD CONSTRAINT registry_tools_server_id_check CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$');
ALTER TABLE registry_risk_floor DROP CONSTRAINT registry_risk_floor_server_id_check;
ALTER TABLE registry_risk_floor ADD CONSTRAINT registry_risk_floor_server_id_check CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$');
ALTER TABLE kill_switches DROP CONSTRAINT kill_switches_server_id_check;
ALTER TABLE kill_switches ADD CONSTRAINT kill_switches_server_id_check CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$');

-- The registry of servers (C5 ServerConfig): the only list of servers.
CREATE TABLE servers (
    server_id    text PRIMARY KEY CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$'),
    system       text        NOT NULL UNIQUE CHECK (system ~ '^[a-z][a-z0-9]{1,30}$'),
    internal_url text        NOT NULL CHECK (internal_url ~ '^https://' AND char_length(internal_url) <= 255),
    tls_name     text        NOT NULL CHECK (tls_name ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    credential   jsonb       NOT NULL,
    enabled      boolean     NOT NULL,
    adapter      boolean     NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (server_id = 'mcp-' || system)
);

-- The policy fragment and the resource type declarations of a server (policiesHash covers both): the approved ones, and the ones that
-- wait for an administrator (a first registration, a changed manifest, or what a running server presented).
CREATE TABLE registry_policies (
    server_id               text PRIMARY KEY CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$'),
    approved_hash           text,
    approved_policies       jsonb,
    approved_resource_types jsonb,
    approved_version        text,
    pending_hash            text,
    pending_policies        jsonb,
    pending_resource_types  jsonb,
    pending_version         text,
    pending_source          text CHECK (pending_source IN ('ci', 'server')),
    CHECK ((approved_hash IS NULL) = (approved_policies IS NULL) AND (approved_hash IS NULL) = (approved_resource_types IS NULL)),
    CHECK ((pending_hash IS NULL) = (pending_policies IS NULL) AND (pending_hash IS NULL) = (pending_resource_types IS NULL)
        AND (pending_hash IS NULL) = (pending_source IS NULL))
);

-- A Cedar namespace belongs to the server that declared it first, until that server is deleted.
CREATE TABLE registry_namespaces (
    namespace text PRIMARY KEY CHECK (namespace ~ '^[A-Z][A-Za-z0-9]{0,30}$'),
    server_id text NOT NULL CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$')
);

-- One row: the revision of the policy data (a counter that only rises, raised by every change of the mapping, the overrides, the
-- allowed clients and the approvals), the scope mapping (the whole document) and the allowed clients this data was last served with.
CREATE TABLE policy_state (
    id              smallint PRIMARY KEY CHECK (id = 1),
    revision        bigint NOT NULL CHECK (revision >= 1),
    scope_mapping   jsonb  NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(scope_mapping) = 'array'),
    allowed_clients text   NOT NULL DEFAULT ''
);
INSERT INTO policy_state (id, revision) VALUES (1, 1);

CREATE TABLE policy_overrides (
    id     text PRIMARY KEY CHECK (id ~ '^override-[a-z0-9][a-z0-9-]{0,54}$'),
    target text        NOT NULL CHECK (target ~ '^(gateway|all-servers|mcp-[a-z][a-z0-9]{1,30})$'),
    text   text        NOT NULL CHECK (char_length(text) BETWEEN 1 AND 8000),
    set_by text        NOT NULL CHECK (char_length(set_by) BETWEEN 1 AND 255),
    set_at timestamptz NOT NULL DEFAULT now()
);

-- The instances that are already running read the registry again when this counter moves.
UPDATE registry_changes SET version = version + 1 WHERE id = 1;
