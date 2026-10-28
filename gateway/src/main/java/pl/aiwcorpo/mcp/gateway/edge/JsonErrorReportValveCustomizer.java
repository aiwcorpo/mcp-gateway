package pl.aiwcorpo.mcp.gateway.edge;

import java.io.IOException;
import java.io.Writer;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.StandardHost;
import org.apache.catalina.valves.ErrorReportValve;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;

/**
 * Tomcat answers some errors itself, before Spring is reached (malformed request line, bad escapes). Its default
 * page is HTML, which CC-089 forbids on public routes, so the host gets an error valve that writes the same
 * JSON as {@link JsonErrorController}.
 */
public final class JsonErrorReportValveCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        factory.addContextCustomizers((Context context) -> {
            if (context.getParent() instanceof StandardHost host) {
                host.setErrorReportValveClass(JsonErrorReportValve.class.getName());
            }
        });
    }

    /** Public so that Tomcat can instantiate it by name. */
    public static final class JsonErrorReportValve extends ErrorReportValve {

        @Override
        protected void report(Request request, Response response, Throwable throwable) {
            int status = response.getStatus();
            if (status < 400 || response.getContentWritten() > 0 || response.isCommitted()) {
                return;
            }
            try {
                response.setHeader("X-Content-Type-Options", "nosniff");
                response.setHeader("Content-Security-Policy", PublicEdgeFilter.CONTENT_SECURITY_POLICY);
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                Writer writer = response.getReporter();
                if (writer != null) {
                    writer.write(JsonErrorController.body(status));
                    response.finishResponse();
                }
            } catch (IOException | IllegalStateException e) {
                // The client is gone or the response was committed meanwhile; nothing left to report.
            }
        }
    }
}
