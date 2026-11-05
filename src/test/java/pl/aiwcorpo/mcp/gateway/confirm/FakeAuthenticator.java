package pl.aiwcorpo.mcp.gateway.confirm;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.function.Consumer;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.broker.AuthenticatorPort;

/** The broker's authenticator as the vectors describe it: its answers are input, its calls are counted. */
final class FakeAuthenticator implements AuthenticatorPort {

    State state = State.ACTIVE;
    boolean burnFails;
    final Deque<Verdict> answers = new ArrayDeque<>();
    int verifyCalls;
    int burnCalls;
    /** Runs once, inside the next verify, before it answers: an owner's cancel that arrives while the code is checked. */
    Runnable duringVerify;
    Consumer<String> onVerify = code -> { };

    @Override
    public State state(GatewayUser user, String tool, String requestId) {
        return state;
    }

    @Override
    public Verdict verify(GatewayUser user, String tool, String code, String requestId) {
        verifyCalls++;
        onVerify.accept(code);
        if (duringVerify != null) {
            Runnable run = duringVerify;
            duringVerify = null;
            run.run();
        }
        return answers.isEmpty() ? new Verdict("unavailable", 0) : answers.poll();
    }

    @Override
    public boolean invalidateCodes(GatewayUser user, String tool, String requestId) {
        if (burnFails) {
            return false;
        }
        burnCalls++;
        return true;
    }
}
