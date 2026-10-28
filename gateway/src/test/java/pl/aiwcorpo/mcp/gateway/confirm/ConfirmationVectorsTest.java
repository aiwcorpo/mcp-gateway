package pl.aiwcorpo.mcp.gateway.confirm;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.broker.AuthenticatorPort;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The vectors of {@code confirmation-binding/} (mcp-contracts 3.0.2) run through the real {@link ConfirmationService}
 * with an in-memory store and a scripted broker: what the reference rules of the contract say must be what the gateway does.
 */
class ConfirmationVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String SUB = "6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11";
    private static final GatewayUser USER = new GatewayUser(SUB, "alice", "claude-code", List.of(), "t");

    /** Clock that the test moves. */
    private static final class TestClock extends Clock {
        final AtomicReference<Instant> now = new AtomicReference<>(Instant.EPOCH);

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }

    private static final class Harness {
        final TestClock clock = new TestClock();
        final InMemoryConfirmationStore store = new InMemoryConfirmationStore(0);
        final FakeAuthenticator broker = new FakeAuthenticator();
        final AtomicInteger step = new AtomicInteger();
        final List<pl.aiwcorpo.mcp.gateway.audit.AuditEvent> events = new ArrayList<>();
        final AuditLog audit = new AuditLog();
        final ConfirmationService service;

        Harness() {
            audit.listen(events::add);
            service = new ConfirmationService(store, broker, audit, "mcp-gateway", clock, 3, () -> "new-" + step.get());
        }
    }

    @TestFactory
    List<DynamicTest> everyVector() {
        List<Vectors.Vector> vectors = Vectors.of("confirmation-binding");
        assertThat(vectors).hasSizeGreaterThanOrEqualTo(77);
        return vectors.stream().map(v -> DynamicTest.dynamicTest(v.name(), () -> run(v.document()))).toList();
    }

    private static void run(JsonNode vector) throws Exception {
        switch (vector.path("kind").asString()) {
            case "first-call" -> firstCall(vector);
            case "retry" -> retry(vector);
            case "first-calls-parallel" -> parallelFirstCalls(vector);
            case "retries-parallel" -> parallelRetries(vector);
            default -> throw new AssertionError("unknown kind in " + vector.path("description").asString());
        }
    }

    // ------------------------------------------------------------------ first-call

    private static void firstCall(JsonNode vector) {
        Harness h = new Harness();
        h.clock.now.set(Instant.parse(vector.path("at").asString()));
        h.broker.state = authenticator(vector.path("authenticator").asString());
        h.store.put(SUB, state(vector.path("pendingCalls")));
        h.broker.burnFails = "failed".equals(vector.path("burn").asString(null));
        Set<String> before = ids(h.store.get(SUB));
        Set<String> notReplacedBefore = notSuperseded(h.store.get(SUB));

        ConfirmationService.FirstCallResult result = h.service.firstCall(info(vector.path("call"), h));

        JsonNode expected = vector.path("expected");
        assertThat(outcomeOf(result)).as(vector.path("description").asString()).isEqualTo(expected.path("outcome").asString());
        if (expected.has("register")) {
            assertThat(result instanceof ConfirmationService.FirstCallResult.Register).isEqualTo(expected.path("register").asBoolean());
        }
        if (expected.has("pendingCreated")) {
            boolean created = result instanceof ConfirmationService.FirstCallResult.Pending p
                    && !before.contains(p.call().confirmationId());
            assertThat(created).isEqualTo(expected.path("pendingCreated").asBoolean());
        }
        if (expected.has("expiresAt") && result instanceof ConfirmationService.FirstCallResult.Pending p) {
            assertThat(Instant.ofEpochMilli(p.call().expiresAt(ConfirmationRules.TTL_MILLIS)))
                    .isEqualTo(Instant.parse(expected.path("expiresAt").asString()));
        }
        if (expected.has("confirmationId")) {
            assertThat(((ConfirmationService.FirstCallResult.Pending) result).call().confirmationId())
                    .isEqualTo(expected.path("confirmationId").asString());
        }
        if (expected.has("retryAfterSeconds")) {
            long retry = result instanceof ConfirmationService.FirstCallResult.Blocked b ? b.retryAfterSeconds()
                    : ((ConfirmationService.FirstCallResult.RateLimited) result).retryAfterSeconds();
            assertThat(retry).isEqualTo(expected.path("retryAfterSeconds").asLong());
        }
        if (expected.has("supersededIds")) {
            assertThat(supersededNow(h.store.get(SUB), notReplacedBefore)).containsExactlyInAnyOrderElementsOf(strings(expected.path("supersededIds")));
        }
        if (expected.has("invalidatedCodes")) {
            assertThat(h.broker.burnCalls > 0).isEqualTo(expected.path("invalidatedCodes").asBoolean());
        } else {
            assertThat(h.broker.burnCalls).as("no burn expected").isZero();
        }
    }

    // ------------------------------------------------------------------ retry

    private static void retry(JsonNode vector) {
        Harness h = new Harness();
        JsonNode attempt = vector.path("attempt");
        h.clock.now.set(Instant.parse(attempt.path("at").asString()));
        JsonNode pending = vector.path("pending");
        if (pending.isObject()) {
            h.store.put(pending.path("sub").asString(SUB), state(JSON.createArrayNode().add(pending)));
        }
        h.broker.answers.add(verdict(vector.path("verification")));
        String attemptSub = attempt.path("sub").asString(SUB);

        ConfirmationService.RetryResult result = h.service.retry(retryInfo(attempt, h), code(attempt));

        JsonNode expected = vector.path("expected");
        assertThat(retryOutcome(result)).as(vector.path("description").asString()).isEqualTo(expected.path("outcome").asString());
        assertThat(h.broker.verifyCalls > 0).isEqualTo(expected.path("verifyCalled").asBoolean());
        if (expected.has("register")) {
            assertThat(result instanceof ConfirmationService.RetryResult.Register).isEqualTo(expected.path("register").asBoolean());
        }
        if (expected.has("retryAfterSeconds")) {
            assertThat(((ConfirmationService.RetryResult.RateLimited) result).retryAfterSeconds())
                    .isEqualTo(expected.path("retryAfterSeconds").asLong());
        }
        if (expected.has("auditReason")) {
            assertThat(h.events).isNotEmpty();
            assertThat(h.events.getLast().view().get("reason")).as("audit reason of " + vector.path("description").asString())
                    .isEqualTo(expected.path("auditReason").asString());
        }
        PendingCall after = h.store.get(pending.path("sub").asString(SUB)).find(pending.path("confirmationId").asString()).orElse(null);
        if (expected.has("pendingConsumed") && h.broker.verifyCalls > 0) {
            assertThat(after == null || after.ended() != null).isEqualTo(expected.path("pendingConsumed").asBoolean());
        }
        if (expected.has("attemptsLeft") && after != null && h.broker.verifyCalls > 0) {
            int left = after.attemptsLeft() + (result instanceof ConfirmationService.RetryResult.Execute ? 1 : 0);
            assertThat(left).isEqualTo(expected.path("attemptsLeft").asInt());
        }
    }

    // ------------------------------------------------------------------ parallel first calls

    private static void parallelFirstCalls(JsonNode vector) {
        Harness h = new Harness();
        long at = Instant.parse(vector.path("at").asString()).toEpochMilli();
        h.clock.now.set(Instant.ofEpochMilli(at));
        h.broker.state = authenticator(vector.path("authenticator").asString());
        h.store.put(SUB, state(vector.path("pendingCalls")));
        List<JsonNode> steps = new ArrayList<>();
        if (vector.has("steps")) {
            vector.path("steps").forEach(steps::add);
        } else {
            vector.path("calls").forEach(c -> steps.add(JSON.createObjectNode().set("call", c)));
        }
        JsonNode expected = vector.path("expected");
        List<String> outcomes = new ArrayList<>();
        List<List<String>> superseded = new ArrayList<>();
        List<Object> previews = new ArrayList<>();
        List<Object> cancels = new ArrayList<>();
        List<Object> burns = new ArrayList<>();
        for (int i = 0; i < steps.size(); i++) {
            JsonNode step = steps.get(i);
            h.step.set(i);
            Set<String> before = notSuperseded(h.store.get(SUB));
            outcomes.add(null);
            previews.add(null);
            cancels.add(null);
            burns.add(null);
            if (step.has("call")) {
                h.broker.burnFails = "failed".equals(step.path("burn").asString(null));
                ConfirmationService.FirstCallResult result = h.service.firstCall(info(step.get("call"), h));
                outcomes.set(i, outcomeOf(result));
            } else if (step.has("preview")) {
                boolean viewed = markViewed(h, step.path("preview").asString());
                previews.set(i, viewed ? null : (Object) 404);
            } else if (step.has("cancel")) {
                h.broker.burnFails = "failed".equals(step.path("burn").asString(null));
                int burnedBefore = h.broker.burnCalls;
                ConfirmationService.CancelResult result = h.service.cancel(USER, "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e00",
                        step.path("cancel").asString());
                cancels.set(i, switch (result) {
                    case ConfirmationService.CancelResult.Cancelled c -> (Object) Boolean.TRUE;
                    case ConfirmationService.CancelResult.NotFound n -> (Object) 404;
                    case ConfirmationService.CancelResult.Unavailable u -> (Object) 503;
                });
                burns.set(i, result instanceof ConfirmationService.CancelResult.Cancelled ? (Object) (h.broker.burnCalls > burnedBefore) : null);
            }
            superseded.add(supersededNow(h.store.get(SUB), before));
        }
        String why = vector.path("description").asString();
        if (expected.has("outcomes")) {
            assertThat(outcomes).as(why).isEqualTo(strings(expected.path("outcomes")));
        }
        if (expected.has("supersededIds")) {
            List<List<String>> want = new ArrayList<>();
            expected.path("supersededIds").forEach(list -> want.add(strings(list)));
            assertThat(superseded).as(why).isEqualTo(want);
        }
        if (expected.has("pendingIds")) {
            List<String> pending = h.store.get(SUB).calls().stream().filter(c -> c.supersededBy() == null && c.ended() == null)
                    .map(PendingCall::confirmationId).toList();
            assertThat(pending).as(why).containsExactlyInAnyOrderElementsOf(strings(expected.path("pendingIds")));
        }
        if (expected.has("previews")) {
            assertThat(previews).as(why).isEqualTo(objects(expected.path("previews")));
        }
        if (expected.has("cancels")) {
            assertThat(cancels).as(why).isEqualTo(objects(expected.path("cancels")));
        }
        if (expected.has("burns")) {
            assertThat(burns).as(why).isEqualTo(objects(expected.path("burns")));
        }
    }

    private static boolean markViewed(Harness h, String id) {
        try {
            return h.service.markViewed(SUB, id);
        } catch (ConfirmationStore.StoreUnavailableException e) {
            throw new AssertionError(e);
        }
    }

    // ------------------------------------------------------------------ parallel retries

    private static void parallelRetries(JsonNode vector) {
        Harness h = new Harness();
        h.clock.now.set(Instant.parse(vector.path("at").asString()));
        JsonNode pending = vector.path("pending");
        h.store.put(SUB, state(JSON.createArrayNode().add(pending)));
        List<String> outcomes = new ArrayList<>();
        for (JsonNode item : vector.path("attempts")) {
            if (item.path("cancel").asBoolean(false)) {
                ConfirmationService.CancelResult result = h.service.cancel(USER, "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e00",
                        pending.path("confirmationId").asString());
                outcomes.add(result instanceof ConfirmationService.CancelResult.Cancelled ? "cancelled" : "not_found");
                continue;
            }
            h.broker.answers.add(verdict(item.path("verification")));
            if (item.path("cancelDuringVerification").asBoolean(false)) {
                h.broker.duringVerify = () -> h.service.cancel(USER, "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e00",
                        pending.path("confirmationId").asString());
            }
            outcomes.add(retryOutcome(h.service.retry(retryInfo(item.path("attempt"), h), code(item.path("attempt")))));
        }
        JsonNode expected = vector.path("expected");
        String why = vector.path("description").asString();
        assertThat(outcomes).as(why).isEqualTo(strings(expected.path("outcomes")));
        assertThat(h.broker.verifyCalls).as(why).isEqualTo(expected.path("brokerCalls").asInt());
        PendingCall after = h.store.get(SUB).find(pending.path("confirmationId").asString()).orElse(null);
        boolean waiting = after != null && after.ended() == null;
        if (expected.path("attemptsLeft").isNull()) {
            assertThat(waiting).as(why + " (no waiting record expected)").isFalse();
        } else {
            assertThat(waiting).isTrue();
            assertThat(after.attemptsLeft()).as(why).isEqualTo(expected.path("attemptsLeft").asInt());
        }
    }

    // ------------------------------------------------------------------ conversions

    private static UserConfirmations state(JsonNode calls) {
        List<PendingCall> list = new ArrayList<>();
        for (JsonNode c : calls) {
            list.add(new PendingCall(c.path("confirmationId").asString(), c.path("serverId").asString(), c.path("tool").asString(),
                    c.path("risk").asString(), c.path("argsSha256").asString(), millis(c.path("createdAt")),
                    c.path("attemptsLeft").asInt(3), c.has("previewViewedAt") ? millis(c.path("previewViewedAt")) : null,
                    c.path("ended").asString(null), c.path("burned").asBoolean(false), c.path("supersededBy").asString(null),
                    c.has("cancelledAt") ? millis(c.path("cancelledAt")) : null, "claude-code", null,
                    new PendingCall.Display("jira__delete_issue", "jira", null, List.of(), "jira__delete_issue (jira):")));
        }
        return new UserConfirmations(list);
    }

    private static long millis(JsonNode iso) {
        return Instant.parse(iso.asString()).toEpochMilli();
    }

    private static ConfirmationService.CallInfo info(JsonNode call, Harness h) {
        JsonNode arguments = call.path("arguments");
        return infoFor(call.path("serverId").asString(), call.path("tool").asString(), call.path("risk").asString(), arguments, h, SUB);
    }

    private static ConfirmationService.CallInfo retryInfo(JsonNode attempt, Harness h) {
        return infoFor(attempt.path("serverId").asString(), attempt.path("tool").asString(), "DESTRUCTIVE",
                attempt.path("arguments"), h, attempt.path("sub").asString(SUB));
    }

    private static ConfirmationService.CallInfo infoFor(String serverId, String tool, String risk, JsonNode arguments, Harness h,
                                                        String sub) {
        tools.jackson.databind.node.ObjectNode withoutCode = ((tools.jackson.databind.node.ObjectNode) arguments).deepCopy();
        withoutCode.remove("confirmation_code");
        ConfirmationRules.Operation operation = new ConfirmationRules.Operation(serverId, tool, risk,
                OperationDescription.argumentsHash(withoutCode));
        PendingCall.Display display = new PendingCall.Display("jira__" + tool, "jira", null, List.of(), "jira__" + tool + " (jira):");
        return new ConfirmationService.CallInfo(new GatewayUser(sub, "alice", "claude-code", List.of(), "t"), "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e01", null, null, serverId, tool, operation,
                display);
    }

    private static String code(JsonNode attempt) {
        return attempt.path("arguments").path("confirmation_code").asString("000000");
    }

    private static AuthenticatorPort.State authenticator(String value) {
        return switch (value) {
            case "none" -> AuthenticatorPort.State.NONE;
            case "disabled" -> AuthenticatorPort.State.DISABLED;
            case "unavailable" -> AuthenticatorPort.State.UNAVAILABLE;
            default -> AuthenticatorPort.State.ACTIVE;
        };
    }

    private static AuthenticatorPort.Verdict verdict(JsonNode verification) {
        String result = verification.path("result").asString("error");
        boolean known = Set.of("ok", "invalid", "replayed", "burned", "locked", "disabled", "not_registered").contains(result);
        return new AuthenticatorPort.Verdict(known ? result : "unavailable", verification.path("retryAfterSeconds").asInt(0));
    }

    private static String outcomeOf(ConfirmationService.FirstCallResult result) {
        return switch (result) {
            case ConfirmationService.FirstCallResult.Pending p -> "confirmation_required";
            case ConfirmationService.FirstCallResult.Register r -> "confirmation_required";
            case ConfirmationService.FirstCallResult.Blocked b -> "confirmation_blocked";
            case ConfirmationService.FirstCallResult.RateLimited r -> "rate_limited";
            case ConfirmationService.FirstCallResult.Unavailable u -> "upstream_unavailable";
        };
    }

    private static String retryOutcome(ConfirmationService.RetryResult result) {
        return switch (result) {
            case ConfirmationService.RetryResult.Execute e -> "execute";
            case ConfirmationService.RetryResult.Failed f -> "confirmation_failed";
            case ConfirmationService.RetryResult.Superseded s -> "confirmation_superseded";
            case ConfirmationService.RetryResult.Cancelled c -> "confirmation_cancelled";
            case ConfirmationService.RetryResult.RateLimited r -> "rate_limited";
            case ConfirmationService.RetryResult.Register r -> "confirmation_required";
            case ConfirmationService.RetryResult.Unavailable u -> "upstream_unavailable";
        };
    }

    private static Set<String> ids(UserConfirmations state) {
        return state.calls().stream().map(PendingCall::confirmationId).collect(java.util.stream.Collectors.toSet());
    }

    private static Set<String> notSuperseded(UserConfirmations state) {
        return state.calls().stream().filter(c -> c.supersededBy() == null).map(PendingCall::confirmationId)
                .collect(java.util.stream.Collectors.toSet());
    }

    /** Calls that were not replaced before and are replaced now. */
    private static List<String> supersededNow(UserConfirmations state, Set<String> notReplacedBefore) {
        return state.calls().stream().filter(c -> c.supersededBy() != null && notReplacedBefore.contains(c.confirmationId()))
                .map(PendingCall::confirmationId).toList();
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.isNull() ? null : n.asString()));
        return out;
    }

    private static List<Object> objects(JsonNode array) {
        List<Object> out = new ArrayList<>();
        array.forEach(n -> out.add(n.isNull() ? null : n.isBoolean() ? (Object) n.asBoolean() : (Object) n.asInt()));
        return out;
    }
}
