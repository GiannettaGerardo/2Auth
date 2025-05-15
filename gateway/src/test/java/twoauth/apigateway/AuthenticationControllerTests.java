package twoauth.apigateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import twoauth.apigateway.model.User;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthenticationControllerTests
{
    private AuthenticationController authController;
    private ExchangeFunction exchangeFunction;

    @BeforeEach
    void setup() {
        exchangeFunction = mock(ExchangeFunction.class);
        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        ObjectMapper objectMapper = new ObjectMapper();
        ServerSecurityContextRepository securityContextRepository = mock(ServerSecurityContextRepository.class);
        authController = new AuthenticationController(
                "localhost", -1, true, securityContextRepository, webClient, objectMapper
        );
    }

    private void mockResponse(HttpStatus status, String body) {
        var builder = ClientResponse.create(status)
                .header("Content-Type", "application/json");

        if (body != null)
            builder.body(body);

        var clientResponse = builder.build();

        when(exchangeFunction.exchange(any(ClientRequest.class))).thenReturn(Mono.just(clientResponse));
    }

    @Test
    void registration_ReturnsOk_WhenBackendReturns200WithEmptyBody()
    {
        mockResponse(HttpStatus.OK, null);

        Mono<ResponseEntity<Object>> response = authController.registration(Mockito.mock(User.class));

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.OK)
                .verifyComplete();
    }

    @Test
    void registration_ReturnsOk_WhenBackendReturns200WithNotEmptyBody()
    {
        mockResponse(HttpStatus.OK, "{\"status\": \"OK\", \"message\": \"QWERTY\"}");

        Mono<ResponseEntity<Object>> response = authController.registration(Mockito.mock(User.class));

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.OK)
                .verifyComplete();
    }

    @Test
    void registration_ReturnsBadRequest_WhenBackendReturnsBadRequest()
    {
        mockResponse(
                HttpStatus.BAD_REQUEST,
                "{\"status\": \"BAD REQUEST\", \"error\": \"QWERTY\"}"
        );

        Mono<ResponseEntity<Object>> response = authController.registration(Mockito.mock(User.class));

        StepVerifier.create(response)
                .expectNextMatches(nextResponse ->
                        nextResponse.getStatusCode() == HttpStatus.BAD_REQUEST
                        && nextResponse.getBody() instanceof String s
                        && "QWERTY".equals(s)
                )
                .verifyComplete();
    }

    @Test
    void registration_ReturnsUnauthorized_WhenBackendReturns500()
    {
        mockResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "{\"status\": \"INTERNAL_SERVER_ERROR\", \"error\": \"QWERTY\"}"
        );

        Mono<ResponseEntity<Object>> response = authController.registration(Mockito.mock(User.class));

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verifyComplete();
    }
}
