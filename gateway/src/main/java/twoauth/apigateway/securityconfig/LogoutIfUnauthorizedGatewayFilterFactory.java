package twoauth.apigateway.securityconfig;

import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.header.ClearSiteDataServerHttpHeadersWriter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

/**
 * If a proxied request returns 401 UNAUTHORIZED, this filter does a complete logout.
 */
@Component
class LogoutIfUnauthorizedGatewayFilterFactory extends AbstractGatewayFilterFactory<Object>
{
    private final ServerSecurityContextRepository securityContextRepository;
    private final CookieServerCsrfTokenRepository csrfTokenRepository;
    private final ClearSiteDataServerHttpHeadersWriter headersWriter;

    public LogoutIfUnauthorizedGatewayFilterFactory(
            ServerSecurityContextRepository securityContextRepository,
            CookieServerCsrfTokenRepository csrfTokenRepository
    ) {
        this.securityContextRepository = securityContextRepository;
        this.csrfTokenRepository = csrfTokenRepository;
        this.headersWriter = new ClearSiteDataServerHttpHeadersWriter(ClearSiteDataServerHttpHeadersWriter.Directive.ALL);
    }

    @Override
    public GatewayFilter apply(Object config) {
        return new LogoutIfUnauthorizedGatewayFilter();
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.emptyList();
    }

    class LogoutIfUnauthorizedGatewayFilter implements GatewayFilter, Ordered
    {
        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            return chain.filter(exchange.mutate().response(new LogoutIfUnauthorizedHttpResponse(exchange)).build());
        }

        @Override
        public int getOrder() {
            return NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1;
        }
    }

    protected class LogoutIfUnauthorizedHttpResponse extends ServerHttpResponseDecorator
    {
        private final ServerWebExchange exchange;

        public LogoutIfUnauthorizedHttpResponse(ServerWebExchange exchange) {
            super(exchange.getResponse());
            this.exchange = exchange;
        }

        @Override
        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body)
        {
            final var statusCode = getStatusCode();
            if (statusCode == null || !HttpStatus.UNAUTHORIZED.isSameCodeAs(statusCode))
                return super.writeWith(body);

            return securityContextServerLogout()
                    .then(webSessionServerLogout())
                    .then(csrfServerLogout())
                    .then(headerWriterServerLogout())
                    .then(super.writeWith(body));
        }

        @Override
        public Mono<Void> writeAndFlushWith(Publisher<? extends Publisher<? extends DataBuffer>> body) {
            return writeWith(Flux.from(body).flatMapSequential(p -> p));
        }

        private Mono<Void> securityContextServerLogout() {
            return securityContextRepository.save(exchange, (SecurityContext)null);
        }

        private Mono<Void> webSessionServerLogout() {
            return exchange.getSession().flatMap(WebSession::invalidate);
        }

        private Mono<Void> csrfServerLogout() {
            return csrfTokenRepository.saveToken(exchange, (CsrfToken)null);
        }

        private Mono<Void> headerWriterServerLogout() {
            return headersWriter.writeHttpHeaders(exchange);
        }
    }
}
