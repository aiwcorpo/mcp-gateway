-- The manifest (C6) the gateway holds as the approved definitions of one server; replaced as a whole on registration.
CREATE TABLE registry_servers (
    server_id     text PRIMARY KEY CHECK (server_id ~ '^mcp-[a-z]{2,32}$'),
    manifest      jsonb       NOT NULL,
    source        text        NOT NULL CHECK (source IN ('ci', 'bootstrap')),
    registered_at timestamptz NOT NULL DEFAULT now()
);
