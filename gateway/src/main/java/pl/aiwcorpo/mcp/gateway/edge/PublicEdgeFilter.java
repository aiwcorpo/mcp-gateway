package pl.aiwcorpo.mcp.gateway.edge;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

/**
 * Rules of the single public origin (CC-089) that the gateway keeps even when the reverse proxy is bypassed:
 * {@code nosniff} and a CSP that forbids everything on every response (errors included, this filter also runs for
 * error dispatches), no {@code Set-Cookie} ever, and no {@code Cookie} from the client: the portal's session
 * cookies are sent to {@code /s/} and {@code /v/} too (Path=/), and nothing in the gateway may see them (C3).
 */
public final class PublicEdgeFilter extends OncePerRequestFilter {

    public static final String CONTENT_SECURITY_POLICY = "default-src 'none'; sandbox";

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
        chain.doFilter(new WithoutCookies(request), new WithoutSetCookie(response));
    }

    private static boolean isCookieHeader(String name) {
        return name != null && "cookie".equals(name.toLowerCase(Locale.ROOT));
    }

    private static final class WithoutCookies extends HttpServletRequestWrapper {

        WithoutCookies(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getHeader(String name) {
            return isCookieHeader(name) ? null : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return isCookieHeader(name) ? Collections.emptyEnumeration() : super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames()).stream().filter(n -> !isCookieHeader(n)).toList();
            return Collections.enumeration(names);
        }

        @Override
        public Cookie[] getCookies() {
            return null;
        }
    }

    private static final class WithoutSetCookie extends HttpServletResponseWrapper {

        WithoutSetCookie(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void addCookie(Cookie cookie) {
        }

        @Override
        public void setHeader(String name, String value) {
            if (!"set-cookie".equals(name == null ? null : name.toLowerCase(Locale.ROOT))) {
                super.setHeader(name, value);
            }
        }

        @Override
        public void addHeader(String name, String value) {
            if (!"set-cookie".equals(name == null ? null : name.toLowerCase(Locale.ROOT))) {
                super.addHeader(name, value);
            }
        }
    }
}
