-- The approved definition of every tool of a server and, next to it, the definition that waits for an administrator
-- (CC-097, CC-133, CC-162). registry_servers keeps the last accepted manifest (version, credential, resource types); the tools
-- in force are here. A row has an approved entry, a pending one, or both (a changed definition of an approved tool).
-- credential is the credential object of the manifest the entry was approved or submitted with: it is part of the hash.
CREATE TABLE registry_tools (
    server_id           text NOT NULL CHECK (server_id ~ '^mcp-[a-z]{2,32}$'),
    tool                text NOT NULL CHECK (char_length(tool) BETWEEN 1 AND 64),
    approved_entry      jsonb,
    approved_hash       text,
    approved_version    text,
    approved_credential jsonb,
    pending_entry       jsonb,
    pending_hash        text,
    pending_version     text,
    pending_change      text CHECK (pending_change IN ('new', 'changed')),
    pending_source      text CHECK (pending_source IN ('ci', 'server')),
    pending_credential  jsonb,
    PRIMARY KEY (server_id, tool),
    CHECK (approved_entry IS NOT NULL OR pending_entry IS NOT NULL),
    CHECK ((approved_entry IS NULL) = (approved_hash IS NULL)),
    CHECK ((pending_entry IS NULL) = (pending_hash IS NULL)),
    CHECK ((pending_entry IS NULL) = (pending_source IS NULL))
);

-- M3 approved a manifest as a whole: every tool of a stored manifest is an approved entry of its version.
INSERT INTO registry_tools (server_id, tool, approved_entry, approved_hash, approved_version, approved_credential)
SELECT s.server_id, t.entry ->> 'name', t.entry, t.entry ->> 'definitionHash', s.manifest ->> 'version',
       COALESCE(s.manifest -> 'credential', 'null'::jsonb)
FROM registry_servers s, jsonb_array_elements(s.manifest -> 'tools') AS t(entry);
