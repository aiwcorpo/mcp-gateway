-- The certificate of a server is pinned to its serverId (SAN <serverId>.internal and CN serverId), so the name is no setting any more.
ALTER TABLE servers DROP COLUMN tls_name;

-- A namespace is owned by the first server whose policies were approved with it. The rows written at registration by the first
-- 2.0.0 build claimed it too early.
DELETE FROM registry_namespaces n
WHERE NOT EXISTS (SELECT 1 FROM registry_policies p WHERE p.server_id = n.server_id AND p.approved_policies ->> 'namespace' = n.namespace);

-- Rows that exist now were written by an earlier build (1.x manifests, or this one before the change): they are taken again when a server
-- of that id is added. Rows that a later removal leaves behind are not legacy and are purged when the id is added.
CREATE TABLE registry_legacy (
    server_id text PRIMARY KEY CHECK (server_id ~ '^mcp-[a-z][a-z0-9]{1,30}$')
);
INSERT INTO registry_legacy (server_id)
SELECT server_id FROM registry_servers
UNION SELECT server_id FROM registry_tools
UNION SELECT server_id FROM registry_policies;

-- The instances that are already running read the registry again when this counter moves.
UPDATE registry_changes SET version = version + 1 WHERE id = 1;
