-- Tools of a server behind an adapter (CC-193, CC-206): the entry has no risk and no action, an administrator classifies it when approving.
-- The classification is part of the approved entry; who gave it and when is kept next to it.
ALTER TABLE registry_tools DROP CONSTRAINT registry_tools_pending_source_check;
ALTER TABLE registry_tools ADD CONSTRAINT registry_tools_pending_source_check CHECK (pending_source IN ('ci', 'server', 'adapter'));
ALTER TABLE registry_tools ADD COLUMN classified_by text CHECK (classified_by IS NULL OR char_length(classified_by) BETWEEN 1 AND 255);
ALTER TABLE registry_tools ADD COLUMN classified_at timestamptz;
ALTER TABLE registry_servers DROP CONSTRAINT registry_servers_source_check;
ALTER TABLE registry_servers ADD CONSTRAINT registry_servers_source_check CHECK (source IN ('ci', 'bootstrap', 'adapter'));
