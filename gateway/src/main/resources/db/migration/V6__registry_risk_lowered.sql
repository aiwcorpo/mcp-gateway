-- A pending entry whose risk is below the risk floor waits for an administrator who accepts the lowering (CC-167).
ALTER TABLE registry_tools ADD COLUMN pending_risk_lowered boolean NOT NULL DEFAULT false;
