-- Static resources, resource templates and prompts of a server's manifest (CC-258, mcp-contracts 8.0.0): the approved entry and, next to it,
-- the one that waits for an administrator, as for tools in registry_tools. The three kinds are told apart by `kind`; a resource and a
-- template share one name space in the manifest, a prompt has its own, so the key is (server, kind, name). There is no credential, risk
-- or floor column: an entry is read only, and its hash already covers the credential object of the manifest.
-- Rows of a server that has none are the normal case; nothing is backfilled and nothing becomes pending by this migration.
CREATE TABLE registry_primitives (
    server_id        text NOT NULL CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$'),
    kind             text NOT NULL CHECK (kind IN ('resource', 'resource_template', 'prompt')),
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    approved_entry   jsonb,
    approved_hash    text,
    approved_version text,
    pending_entry    jsonb,
    pending_hash     text,
    pending_version  text,
    pending_change   text CHECK (pending_change IN ('new', 'changed')),
    pending_source   text CHECK (pending_source IN ('manifest', 'adapter')),
    PRIMARY KEY (server_id, kind, name),
    CHECK (approved_entry IS NOT NULL OR pending_entry IS NOT NULL),
    CHECK ((approved_entry IS NULL) = (approved_hash IS NULL)),
    CHECK ((pending_entry IS NULL) = (pending_hash IS NULL)),
    CHECK ((pending_entry IS NULL) = (pending_source IS NULL)),
    CHECK ((pending_entry IS NULL) = (pending_change IS NULL)),
    CHECK (kind <> 'prompt' OR pending_source IS DISTINCT FROM 'adapter')
);

-- The contractsVersion of the last accepted manifest of a server (CC-258); null for a manifest that does not name one, which means 7.x or
-- older. Nothing reads it before the emission of the new claims is switched on (CC-260, step 5).
ALTER TABLE registry_servers ADD COLUMN contracts_version text
    CHECK (contracts_version IS NULL OR contracts_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$');

-- Emergency switches of one resource or one prompt (CC-265). Apart from kill_switches on purpose: an instance of the previous version reads
-- every row of that table as the switch of a tool and would refuse a tool that happens to share the name. A switch belongs to the address
-- (server, kind, name), not to the manifest, like the others. kind resource covers a static resource and a template of that name.
CREATE TABLE kill_switches_primitive (
    server_id text        NOT NULL CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$'),
    kind      text        NOT NULL CHECK (kind IN ('resource', 'prompt')),
    name      text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    set_by    text        NOT NULL CHECK (char_length(set_by) BETWEEN 1 AND 255),
    set_at    timestamptz NOT NULL DEFAULT now(),
    reason    text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 200),
    PRIMARY KEY (server_id, kind, name)
);
