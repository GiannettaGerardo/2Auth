package twoauth.apigateway.securityconfig;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.session.InMemoryReactiveSessionRegistry;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.PreventLoginServerMaximumSessionsExceededHandler;
import org.springframework.security.web.server.authentication.SessionLimit;
import org.springframework.security.web.server.authentication.logout.*;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.*;

import org.springframework.security.web.server.firewall.StrictServerWebExchangeFirewall;
import org.springframework.security.web.server.header.ClearSiteDataServerHttpHeadersWriter;
import static org.springframework.security.web.server.header.ClearSiteDataServerHttpHeadersWriter.Directive;

import static org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.security.web.server.util.matcher.*;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.InMemoryWebSessionStore;
import org.springframework.web.server.session.WebSessionIdResolver;
import org.springframework.web.server.session.WebSessionStore;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
class SecurityConfiguration
{
    private static final String COMPLETE_LOGOUT_PATH = "/complete-logout";
    private final List<HttpMethod> allowedHttpMethods;

    public SecurityConfiguration(
            @Value("${2Auth.allowedHttpMethods:GET,POST,PUT,DELETE}") List<String> allowedHttpMethods
    ) {
        this.allowedHttpMethods = getHttpMethod(allowedHttpMethods);
    }

    private static List<HttpMethod> getHttpMethod(final List<String> initialHttpMethods)
    {
        if (initialHttpMethods.isEmpty())
            return List.of(HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE);

        boolean isOk = true;
        final var httpMethods = HttpMethod.values();
        for (String method : initialHttpMethods) {
            if (Arrays.stream(httpMethods).noneMatch(m -> m.matches(method))) {
                isOk = false;
                break;
            }
        }
        if (! isOk) {
            return List.of(HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE);
        }
        return initialHttpMethods.stream().map(HttpMethod::valueOf).toList();
    }

    @Bean
    SecurityWebFilterChain securityFilterChain(
            final ServerHttpSecurity http,
            final ServerSecurityContextRepository contextRepository,
            final CorsConfigurationSource corsConfigurationSource,
            final CookieServerCsrfTokenRepository csrfTokenRepository,
            final DelegatingServerLogoutHandler logoutHandler
    ) {
        http
            .headers(headers -> headers
                    .hsts(opt -> opt
                            .maxAge(Duration.ofSeconds(63072000))
                            .includeSubdomains(true)
                            .preload(true))
                    .referrerPolicy(opt -> opt.policy(ReferrerPolicy.NO_REFERRER))
            )
            .csrf(csrf -> csrf
                    .requireCsrfProtectionMatcher(csrfRequestMatcher())
                    .csrfTokenRepository(csrfTokenRepository)
                    .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
                    .accessDeniedHandler(csrfAccessDeniedHandler())
            )
            .cors(cors -> cors
                    .configurationSource(corsConfigurationSource)
            )
            .authorizeExchange(exchanges -> exchanges
                    .pathMatchers(HttpMethod.POST, "/login").permitAll()
                    .pathMatchers(HttpMethod.POST, "/registration").permitAll()
                    .anyExchange().authenticated()
            )
            .exceptionHandling(exceptionHandling -> exceptionHandling
                    .authenticationEntryPoint(customAuthenticationEntryPoint())
            )
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .securityContextRepository(contextRepository)
            .sessionManagement(sessions -> sessions
                    .concurrentSessions(concurrency -> concurrency
                            .maximumSessions(SessionLimit.of(2))
                            .maximumSessionsExceededHandler(new PreventLoginServerMaximumSessionsExceededHandler())
                    )
            )
            .logout(logoutSpec -> logoutSpec
                    .requiresLogout(new OrServerWebExchangeMatcher(
                            ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/logout"),
                            ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, COMPLETE_LOGOUT_PATH)
                    ))
                    .logoutHandler(logoutHandler)
                    .logoutSuccessHandler(new HttpStatusReturningServerLogoutSuccessHandler())
            );

        return http.build();
    }

    @Bean
    StrictServerWebExchangeFirewall httpFirewall() {
        final var firewall = new StrictServerWebExchangeFirewall();
        firewall.setAllowedHttpMethods(allowedHttpMethods);
        return firewall;
    }

    @Bean
    UrlBasedCorsConfigurationSource corsConfigurationSource(
            @Value("${2Auth.allowedOrigins:*}") List<String> allowedOrigins
    ) {
        if (allowedOrigins.isEmpty())
            allowedOrigins = List.of("*");

        final var configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(allowedHttpMethods.stream().map(HttpMethod::name).toList());
        configuration.setAllowCredentials(false);

        final var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * OWASP <a href="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies">Session Management with Cookies</a>
     * <br/>
     * OWASP <a href="https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes">Session Management Cookie Attributes</a>
     */
    @Bean
    WebSessionIdResolver webSessionIdResolver(
            @Value("${server.ssl.enabled:false}") boolean isSslEnabled,
            @Value("${2Auth.customSessionIdName:XYZ_S}") String customSessionIdName
    ) {
        if (customSessionIdName.isBlank())
            customSessionIdName = "XYZ_S";
        customSessionIdName = String.format("__Host-%s", customSessionIdName);

        final var resolver = new CookieWebSessionIdResolver();
        resolver.setCookieName(customSessionIdName);
        resolver.addCookieInitializer(builder -> builder
                .path("/")
                .sameSite("Strict")
                .httpOnly(true)
                .secure(isSslEnabled)
        );
        return resolver;
    }

    @Bean
    ReactiveSessionRegistry reactiveSessionRegistry() {
        return new InMemoryReactiveSessionRegistry();
    }

    @Bean
    WebSessionStore webSessionStore() {
        return new InMemoryWebSessionStore();
    }

    @Bean
    ServerSecurityContextRepository securityContextRepository() {
        return new WebSessionServerSecurityContextRepository();
    }

    @Bean
    DelegatingServerLogoutHandler logoutHandler(
            ReactiveSessionRegistry reactiveSessionRegistry,
            WebSessionStore webSessionStore
    ) {
        return new DelegatingServerLogoutHandler(
                new CompleteLogoutServerLogoutHandler(
                        reactiveSessionRegistry,
                        webSessionStore,
                        COMPLETE_LOGOUT_PATH
                ),
                new SecurityContextServerLogoutHandler(),
                new WebSessionServerLogoutHandler(),
                new HeaderWriterServerLogoutHandler(new ClearSiteDataServerHttpHeadersWriter(Directive.ALL))
        );
    }

    @Bean
    CookieServerCsrfTokenRepository csrfTokenRepository() {
        return CookieServerCsrfTokenRepository.withHttpOnlyFalse();
    }

    @Bean
    WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty()).subscribe();
            return chain.filter(exchange);
        };
    }

    private ServerWebExchangeMatcher csrfRequestMatcher() {
        return new AndServerWebExchangeMatcher(
                new NegatedServerWebExchangeMatcher(
                        ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/login")
                ),
                new NegatedServerWebExchangeMatcher(
                        ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/registration")
                )
        );
    }

    /**
     * @return a Server Access Denied Handler that returns only http status code 401 - UNAUTHORIZED.
     */
    private ServerAccessDeniedHandler csrfAccessDeniedHandler() {
        return (exchange, denied) -> {
            // Only status 401, no message
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        };
    }

    /**
     * @return a Server Authentication Entry Point that returns only http status code 401 - UNAUTHORIZED.
     */
    private ServerAuthenticationEntryPoint customAuthenticationEntryPoint() {
        return (exchange, ex) -> {
            // Only status 401, no header WWW-Authenticate and no message
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        };
    }
}
