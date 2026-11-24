-- The registry of autonomous agents (CC-266, mcp-contracts 8.0.0). An agent is a client of the identity provider with its own service
-- account; the gateway knows it from this row and not from MCP_ALLOWED_CLIENTS. The client in the identity provider is created by an
-- administrator beforehand and the gateway never checks it, so nothing here references anything else.
-- The suspension is part of the row (the emergency switch of an agent): it is written and lifted in the transaction of the change counter
-- like the other switches, so an instance that reads the registry reads the switch with it. The three suspended_* columns are all set or all null.
-- allowed_groups is the ceiling of the groups of the token: -destructive groups and mcp-platform-admin are refused by the API, not stored.
CREATE TABLE agent_clients (
    client_id           text        PRIMARY KEY CHECK (client_id ~ '^agent-[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND char_length(client_id) <= 64),
    service_account_sub text        NOT NULL CHECK (char_length(service_account_sub) BETWEEN 1 AND 255 AND service_account_sub !~ '^system:'),
    owner_sub           text        NOT NULL CHECK (char_length(owner_sub) BETWEEN 1 AND 255),
    max_risk            text        NOT NULL DEFAULT 'READ_ONLY' CHECK (max_risk IN ('READ_ONLY', 'UPDATE')),
    allowed_groups      jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(allowed_groups) = 'array' AND jsonb_array_length(allowed_groups) <= 100),
    delegation_allowed  boolean     NOT NULL DEFAULT false,
    created_by          text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 255),
    created_at          timestamptz NOT NULL DEFAULT now(),
    key_rotated_at      timestamptz,
    suspended_by        text        CHECK (suspended_by IS NULL OR char_length(suspended_by) BETWEEN 1 AND 255),
    suspended_at        timestamptz,
    suspend_reason      text        CHECK (suspend_reason IS NULL OR char_length(suspend_reason) BETWEEN 1 AND 200),
    CHECK ((suspended_by IS NULL) = (suspended_at IS NULL) AND (suspended_by IS NULL) = (suspend_reason IS NULL))
);

-- The owner is looked up on every list with owner=me and on the purge of a user.
CREATE INDEX agent_clients_owner ON agent_clients (owner_sub);
