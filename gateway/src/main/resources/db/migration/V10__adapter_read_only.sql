-- A tool of an adapter is read only (CC-227): the classification UPDATE or DESTRUCTIVE stored before is void. The entry goes back to
-- pending_approval (source adapter, without risk and action, hidden and refused as tool_disabled); the classification stays as the floor of the
-- risk, so that approving it as READ_ONLY is a lowering that needs acceptRiskLowering. A pending entry that was already waiting stays as it is.
INSERT INTO registry_risk_floor (server_id, tool, risk)
SELECT t.server_id, t.tool, CASE t.approved_entry ->> 'risk' WHEN 'DESTRUCTIVE' THEN 2 ELSE 1 END
FROM registry_tools t JOIN registry_servers s ON s.server_id = t.server_id
WHERE s.source = 'adapter' AND t.approved_entry ->> 'risk' IN ('UPDATE', 'DESTRUCTIVE')
ON CONFLICT (server_id, tool) DO UPDATE SET risk = GREATEST(registry_risk_floor.risk, EXCLUDED.risk);

UPDATE registry_tools t
SET pending_entry      = COALESCE(t.pending_entry, t.approved_entry - 'risk' - 'action'),
    pending_hash       = COALESCE(t.pending_hash, t.approved_hash),
    pending_version    = COALESCE(t.pending_version, t.approved_version),
    pending_change     = COALESCE(t.pending_change, 'new'),
    pending_source     = COALESCE(t.pending_source, 'adapter'),
    pending_credential = COALESCE(t.pending_credential, t.approved_credential),
    approved_entry = NULL, approved_hash = NULL, approved_version = NULL, approved_credential = NULL,
    classified_by = NULL, classified_at = NULL
FROM registry_servers s
WHERE s.server_id = t.server_id AND s.source = 'adapter' AND t.approved_entry ->> 'risk' IN ('UPDATE', 'DESTRUCTIVE');
