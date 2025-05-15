package twoauth.apigateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import twoauth.apigateway.model.AuthRequest;
import twoauth.apigateway.model.JwtResponse;
import twoauth.apigateway.model.User;
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

@RestController
class AuthenticationController
{
    private final URI registrationURI;
    private final URI loginURI;
    private final ServerSecurityContextRepository securityContextRepository;
    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public AuthenticationController(
            @Value("${2Auth.backend-domain:localhost}") String backendDomain,
            @Value("${2Auth.backend-port:-1}") int backendPort,
            @Value("${server.ssl.enabled:false}") boolean isSslEnabled,
            ServerSecurityContextRepository securityContextRepository,
            WebClient webClient,
            ObjectMapper objectMapper
    ) {
        final String scheme = isSslEnabled ? "https" : "http";
        try {
            registrationURI = new URI(scheme, null, backendDomain, backendPort, "/registration", null, null);
            loginURI = new URI(scheme, null, backendDomain, backendPort, "/login", null, null);
        }
        catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid backend registration/login URI.");
        }

        this.securityContextRepository = securityContextRepository;
        this.webClient = webClient;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/registration")
    public Mono<ResponseEntity<Object>> registration(@RequestBody final User user)
    {
        return webClient.post()
                .uri(registrationURI)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(user)
                .accept(MediaType.APPLICATION_JSON)
                .acceptCharset(Charset.defaultCharset())
                .retrieve()
                .onStatus(
                        status -> status.isSameCodeAs(HttpStatus.BAD_REQUEST),
                        response -> response
                                .bodyToMono(ErrorWrapper.class)
                                .map(wrapper -> new AuthBadRequestException(wrapper.error()))
                )
                .bodyToMono(Object.class)
                .thenReturn(ResponseEntity.ok().build())
                .doOnSuccess(__ -> user.eraseCredentials())
                .onErrorResume(e -> {
                    user.eraseCredentials();
                    if (e instanceof AuthBadRequestException)
                        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage()));
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
                });
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Object>> login(@RequestBody final AuthRequest request,
                                              final ServerWebExchange exchange) {
        return webClient.post()
                .uri(loginURI)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .accept(MediaType.APPLICATION_JSON)
                .acceptCharset(Charset.defaultCharset())
                .retrieve()
                .onStatus(
                        status -> status.isSameCodeAs(HttpStatus.BAD_REQUEST),
                        response -> response
                                .bodyToMono(ErrorWrapper.class)
                                .map(wrapper -> new AuthBadRequestException(wrapper.error()))
                )
                .bodyToMono(JwtResponse.class)
                .flatMap(response -> {
                    request.eraseCredentials();
                    final SecurityContext context = new SecurityContextImpl(new JwtAuthentication(response.jwt(), objectMapper));
                    return securityContextRepository.save(exchange, context)
                            .thenReturn(ResponseEntity.ok().build());
                })
                .onErrorResume(e -> {
                    request.eraseCredentials();
                    if (e instanceof AuthBadRequestException)
                        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage()));
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
                });
    }

    public record ErrorWrapper(
            String error
    ) {}
}
