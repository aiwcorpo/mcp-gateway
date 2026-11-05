-- Emergency switches of servers and tools (CC-194, A9). A switch belongs to the address (server, tool), not to the manifest: it stays when
-- the tool leaves the manifest and returns with it. An empty tool is the switch of the whole server. No expiry: only a DELETE lifts it.
CREATE TABLE kill_switches (
    server_id text        NOT NULL CHECK (server_id ~ '^mcp-[a-z]{2,32}$'),
    tool      text        NOT NULL DEFAULT '' CHECK (char_length(tool) <= 64),
    set_by    text        NOT NULL CHECK (char_length(set_by) BETWEEN 1 AND 255),
    set_at    timestamptz NOT NULL DEFAULT now(),
    reason    text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 200),
    PRIMARY KEY (server_id, tool)
);

-- One counter, raised in the transaction of every change of the registry or of a switch: an instance looks at it every second and
-- reads the rest only when it moved, so a change made on one instance reaches the others within seconds without a message channel.
CREATE TABLE registry_changes (
    id      smallint PRIMARY KEY CHECK (id = 1),
    version bigint   NOT NULL
);
INSERT INTO registry_changes (id, version) VALUES (1, 0);
