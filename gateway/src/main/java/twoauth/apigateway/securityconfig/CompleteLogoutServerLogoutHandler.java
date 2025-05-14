package twoauth.apigateway.securityconfig;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.session.WebSessionStore;
import reactor.core.publisher.Mono;

final class CompleteLogoutServerLogoutHandler implements ServerLogoutHandler
{
    private final ReactiveSessionRegistry reactiveSessionRegistry;
    private final WebSessionStore webSessionStore;
    private final ServerWebExchangeMatcher completeLogoutPathMatcher;

    public CompleteLogoutServerLogoutHandler(
            final ReactiveSessionRegistry reactiveSessionRegistry,
            final WebSessionStore webSessionStore,
            final String completeLogoutPath
    ) {
        this.reactiveSessionRegistry = reactiveSessionRegistry;
        this.webSessionStore = webSessionStore;
        this.completeLogoutPathMatcher = ServerWebExchangeMatchers.pathMatchers(completeLogoutPath);
    }

    @Override
    public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication)
    {
        return completeLogoutPathMatcher
                .matches(exchange.getExchange())
                .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
                .flatMap(r -> this.reactiveSessionRegistry.getAllSessions(authentication.getPrincipal())
                        .flatMap(session -> session.invalidate().thenReturn(session))
                        .flatMap(session -> this.webSessionStore.removeSession(session.getSessionId()))
                        .then()
                );
    }
}
