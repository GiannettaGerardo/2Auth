package twoauth.apigateway.securityconfig;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.util.Collections;
import java.util.List;

@Component
class JwtTokenRelayGatewayFilterFactory extends AbstractGatewayFilterFactory<Object>
{
    @Override
    public GatewayFilter apply(Object config)
    {
        return (exchange, chain) -> exchange.getPrincipal()
                .filter(JwtAuthentication.class::isInstance)
                .cast(JwtAuthentication.class)
                .map(jwtAuth -> withBearerAuth(exchange, jwtAuth))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.emptyList();
    }

    private ServerWebExchange withBearerAuth(ServerWebExchange exchange, JwtAuthentication jwtAuth) {
        return exchange.mutate()
                .request(r -> r.headers(headers -> headers.setBearerAuth(jwtAuth.getToken())))
                .build();
    }
}
