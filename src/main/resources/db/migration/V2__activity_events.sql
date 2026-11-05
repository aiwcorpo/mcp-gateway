-- Gateway audit events of a user's calls (C8 without arguments), kept 30 days, for /admin/v1/activity and /activity/calls.
-- call_key is the gateway's internal link between the events of one call (a pending confirmation and its retries); it
-- is not part of C8 and never leaves the gateway.
CREATE TABLE activity_events (
    id         bigserial PRIMARY KEY,
    sub        text        NOT NULL CHECK (char_length(sub) BETWEEN 1 AND 255),
    call_key   text        NOT NULL CHECK (char_length(call_key) BETWEEN 1 AND 128),
    ts         timestamptz NOT NULL,
    request_id text        NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 64),
    event      jsonb       NOT NULL
);

CREATE INDEX activity_events_sub_ts ON activity_events (sub, ts DESC);
CREATE INDEX activity_events_sub_call ON activity_events (sub, call_key);
