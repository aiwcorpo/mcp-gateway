-- A definition recorded from a running server (source server, or adapter for a server behind an adapter) left the additionalGroup of the
-- approved entry out, although its hash covers it, so approving it removed the group from the tool. Such a pending entry is cleared, and the
-- next check of the server records it again, now with the group. The pending columns belong together (CHECKs of V5 and V9), so all go at
-- once; the approved entry stays, which is what the CHECK that a row holds an entry needs. A pending entry that was approved already is
-- not found here: the tool has lost its group, and an administrator has to look at it.
UPDATE registry_tools
SET pending_entry        = NULL,
    pending_hash         = NULL,
    pending_version      = NULL,
    pending_change       = NULL,
    pending_source       = NULL,
    pending_credential   = NULL,
    pending_risk_lowered = false
WHERE pending_source IN ('server', 'adapter')
  AND approved_entry ->> 'additionalGroup' IS NOT NULL
  AND pending_entry ->> 'additionalGroup' IS NULL;

-- The instances that are already running read the registry again when this counter moves.
UPDATE registry_changes SET version = version + 1 WHERE id = 1;
