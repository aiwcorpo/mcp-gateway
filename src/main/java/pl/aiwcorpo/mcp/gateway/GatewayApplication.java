package pl.aiwcorpo.mcp.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import pl.aiwcorpo.mcp.gateway.setup.GatewaySetup;

@SpringBootApplication
@ConfigurationPropertiesScan
public class GatewayApplication {

    public static void main(String[] args) {
        if (args.length > 0 && "init".equals(args[0])) {
            System.exit(GatewaySetup.run(args));
        }
        SpringApplication.run(GatewayApplication.class, args);
    }
}
