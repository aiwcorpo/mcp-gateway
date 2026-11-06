-- The additionalGroup an approved entry of a tool names (CC-245, CC-246). Like the risk floor it outlives the tool and the server: a tool
-- that is removed and registered again, or a server that is deleted and added again, cannot come back without the group by the review of
-- a commit alone. An approval by an administrator sets it (or clears it).
CREATE TABLE registry_group_floor (
    server_id        text NOT NULL CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$'),
    tool             text NOT NULL CHECK (char_length(tool) BETWEEN 1 AND 64),
    additional_group text NOT NULL CHECK (additional_group ~ '^mcp-[a-z][a-z0-9]{1,30}-[a-z][a-z0-9-]{0,40}$'),
    PRIMARY KEY (server_id, tool)
);

INSERT INTO registry_group_floor (server_id, tool, additional_group)
SELECT server_id, tool, approved_entry ->> 'additionalGroup' FROM registry_tools WHERE approved_entry ->> 'additionalGroup' IS NOT NULL;

UPDATE registry_changes SET version = version + 1 WHERE id = 1;
