package twoauth.apigateway.securityconfig;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Adapted from
 * <a href="https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa">Spring documentation</a>
 */
final class SpaCsrfTokenRequestHandler extends ServerCsrfTokenRequestAttributeHandler
{
    private final ServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken) {
        /*
         * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of the
         * CsrfToken when it is rendered in the response body.
         */
        this.delegate.handle(exchange, csrfToken);
    }

    @Override
    public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
        /*
         * If the request contains an X-XSRF-TOKEN header, use it. This applies when a single-page
         * application includes the header value automatically, which was obtained via a cookie
         * containing the raw CsrfToken. In all other cases (e.g. if the request contains a request
         * parameter), use XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies
         * when a server-side rendered form includes the _csrf request parameter as a hidden input.
         */
        return Mono
                .justOrEmpty(exchange.getRequest().getHeaders().getFirst(csrfToken.getHeaderName()))
                .switchIfEmpty(this.delegate.resolveCsrfTokenValue(exchange, csrfToken));
    }
}
