CREATE TABLE virtual_servers (
    slug         text PRIMARY KEY CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    owner_sub    text NOT NULL CHECK (char_length(owner_sub) BETWEEN 1 AND 255),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 100),
    tools        jsonb NOT NULL CHECK (jsonb_typeof(tools) = 'array' AND jsonb_array_length(tools) >= 1),
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX virtual_servers_owner ON virtual_servers (owner_sub, created_at);
