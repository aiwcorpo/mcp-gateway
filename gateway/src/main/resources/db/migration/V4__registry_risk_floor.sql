-- The highest risk ever approved for a tool of a server. It is never lowered and never deleted when a tool disappears from
-- a manifest, so a tool cannot be removed and registered again with a lower risk (that needs an administrator, M4).
CREATE TABLE registry_risk_floor (
    server_id text NOT NULL CHECK (server_id ~ '^mcp-[a-z]{2,32}$'),
    tool      text NOT NULL CHECK (char_length(tool) BETWEEN 1 AND 64),
    risk      smallint NOT NULL CHECK (risk BETWEEN 0 AND 2),
    PRIMARY KEY (server_id, tool)
);
