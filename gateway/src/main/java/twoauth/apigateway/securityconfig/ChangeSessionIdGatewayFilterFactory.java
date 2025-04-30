package twoauth.apigateway.securityconfig;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.WebSession;

import java.util.Collections;
import java.util.List;

@Component
public class ChangeSessionIdGatewayFilterFactory extends AbstractGatewayFilterFactory<Object>
{
    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> exchange.getSession()
                .flatMap(WebSession::changeSessionId)
                .then(chain.filter(exchange));
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.emptyList();
    }
}
