-- Rows of an earlier build were adopted by whichever manifest claimed their serverId, which skipped the approval of policies and tools.
-- The serverId now comes from a manifest that is served without authentication, so nothing is adopted any more: a server that is added
-- always starts from nothing (RegistryStore.purgeLeftovers).
DROP TABLE registry_legacy;
