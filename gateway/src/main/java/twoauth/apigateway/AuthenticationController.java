package twoauth.apigateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import twoauth.apigateway.securityconfig.JwtAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.List;

@RestController
public class AuthenticationController
{
    private final URI registrationURI;
    private final URI loginURI;
    private final ServerSecurityContextRepository securityContextRepository;
    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public AuthenticationController(
            @Value("${backend-domain}") String backendDomain,
            @Value("${backend-port}") Integer backendPort,
            @Value("${server.ssl.enabled}") Boolean isHttpsEnabled,
            ServerSecurityContextRepository securityContextRepository,
            WebClient webClient,
            ObjectMapper objectMapper
    ) {
        final String scheme = Boolean.TRUE == isHttpsEnabled ? "https" : "http";
        try {
            registrationURI = new URI(
                    scheme, null, backendDomain, backendPort,
                    "/registration", null, null
            );
            loginURI = new URI(
                    scheme, null, backendDomain, backendPort,
                    "/login", null, null
            );
        }
        catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid backend registration/login URI.");
        }

        this.securityContextRepository = securityContextRepository;
        this.webClient = webClient;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/registration")
    public Mono<ResponseEntity<Object>> registration(
            @RequestBody final User user,
            final ServerWebExchange exchange
    ) {
        return webClient.post()
                .uri(registrationURI)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(user)
                .accept(MediaType.TEXT_PLAIN)
                .acceptCharset(Charset.defaultCharset())
                .retrieve()
                .onStatus(
                        status -> status.isSameCodeAs(HttpStatus.BAD_REQUEST),
                        response -> response.bodyToMono(String.class).map(AuthBadRequestException::new)
                )
                .bodyToMono(String.class)
                .map(username -> {
                    user.erasePassword();
                    return ResponseEntity.ok().build();
                })
                .onErrorResume(e -> {
                    user.erasePassword();
                    if (e instanceof AuthBadRequestException)
                        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage()));
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
                });
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Object>> login(
            @RequestBody final AuthRequest request,
            final ServerWebExchange exchange
    ) {
        return webClient.post()
                .uri(loginURI)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .accept(MediaType.TEXT_PLAIN)
                .acceptCharset(Charset.defaultCharset())
                .retrieve()
                .onStatus(
                        status -> status.isSameCodeAs(HttpStatus.BAD_REQUEST),
                        response -> response.bodyToMono(String.class).map(AuthBadRequestException::new)
                )
                .bodyToMono(String.class)
                .flatMap(jwt -> {
                    request.erasePassword();
                    final SecurityContext context = new SecurityContextImpl(new JwtAuthentication(jwt, objectMapper));
                    return securityContextRepository.save(exchange, context)
                            .thenReturn(ResponseEntity.ok().build());
                })
                .onErrorResume(e -> {
                    request.erasePassword();
                    if (e instanceof AuthBadRequestException)
                        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage()));
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
                });
    }

    public static class AuthRequest {
        private String username;
        private String password;

        private AuthRequest() {}

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public void erasePassword() {
            this.password = null;
        }

        @Override
        public String toString() {
            return "AuthRequest{" +
                    "username='" + username + '\'' +
                    ", password='" + password + '\'' +
                    '}';
        }
    }

    public static class User {
        private String email;
        private String password;
        private String firstName;
        private String lastName;
        private List<String> permissions;

        private User() {}

        public void erasePassword() {
            this.password = null;
        }

        public String getEmail() {
            return email;
        }

        public String getPassword() {
            return password;
        }

        public String getFirstName() {
            return firstName;
        }

        public List<String> getPermissions() {
            return permissions;
        }

        public String getLastName() {
            return lastName;
        }
    }
}
