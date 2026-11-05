package pl.aiwcorpo.mcp.gateway.killswitch;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/** An instance that cannot read the emergency switches refuses calls, so it is not ready either (CC-194, fail-closed). */
public final class KillSwitchHealth implements HealthIndicator {

    private final KillSwitches switches;

    public KillSwitchHealth(KillSwitches switches) {
        this.switches = switches;
    }

    @Override
    public Health health() {
        return switches.readable() ? Health.up().build() : Health.down().build();
    }
}
