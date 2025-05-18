package twoauth.apigateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import twoauth.apigateway.model.AuthRequest;
import twoauth.apigateway.model.User;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthenticationControllerTests
{
    private final ObjectMapper objectMapper = new ObjectMapper();
    private AuthenticationController authController;
    private ExchangeFunction exchangeFunction;
    private ServerSecurityContextRepository securityContextRepository;

    @BeforeEach
    void setup() {
        exchangeFunction = mock(ExchangeFunction.class);
        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        securityContextRepository = mock(ServerSecurityContextRepository.class);
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
        // Mocked response
        mockResponse(HttpStatus.OK, null);

        User mockedUser = Mockito.mock(User.class);
        Mono<ResponseEntity<Object>> response = authController.registration(mockedUser);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.OK)
                .verifyComplete();

        assertNull(mockedUser.getPassword());
    }

    @Test
    void registration_ReturnsOk_WhenBackendReturns200WithNotEmptyBody()
    {
        // Mocked response
        mockResponse(HttpStatus.OK, "{\"status\": \"OK\", \"message\": \"QWERTY\"}");

        User mockedUser = Mockito.mock(User.class);
        Mono<ResponseEntity<Object>> response = authController.registration(mockedUser);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.OK)
                .verifyComplete();

        assertNull(mockedUser.getPassword());
    }

    @Test
    void registration_ReturnsBadRequestWithCustomMessage_WhenBackendReturnsValidBadRequest()
    {
        // Mocked response
        mockResponse(HttpStatus.BAD_REQUEST, "{\"status\": \"BAD REQUEST\", \"error\": \"QWERTY\"}");

        User mockedUser = Mockito.mock(User.class);
        Mono<ResponseEntity<Object>> response = authController.registration(mockedUser);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse ->
                        nextResponse.getStatusCode() == HttpStatus.BAD_REQUEST
                        && nextResponse.getBody() instanceof String s
                        && "QWERTY".equals(s)
                )
                .verifyComplete();

        assertNull(mockedUser.getPassword());
    }

    @Test
    void registration_ReturnsUnauthorized_WhenBadRequestHasAnEmptyBody()
    {
        // Mocked response
        mockResponse(HttpStatus.BAD_REQUEST, null);

        User mockedUser = Mockito.mock(User.class);
        Mono<ResponseEntity<Object>> response = authController.registration(mockedUser);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verifyComplete();

        assertNull(mockedUser.getPassword());
    }

    @Test
    void registration_ReturnsUnauthorized_WhenBadRequestHasAnInvalidBody()
    {
        // Mocked response
        mockResponse(HttpStatus.BAD_REQUEST, "{\"test\": \"test\"}");

        User mockedUser = Mockito.mock(User.class);
        Mono<ResponseEntity<Object>> response = authController.registration(mockedUser);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verifyComplete();

        assertNull(mockedUser.getPassword());
    }

    @Test
    void registration_ReturnsUnauthorized_WhenBackendReturns500()
    {
        // Mocked response
        mockResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "{\"status\": \"INTERNAL_SERVER_ERROR\", \"error\": \"QWERTY\"}"
        );

        User mockedUser = Mockito.mock(User.class);
        Mono<ResponseEntity<Object>> response = authController.registration(mockedUser);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verifyComplete();

        assertNull(mockedUser.getPassword());
    }

    @Test
    void login_ReturnsOk_WhenBackendReturns200WithValidJwt() throws Exception
    {
        AuthRequest mockedAuthRequest = new AuthRequest("test@email.com", "password1234", null);

        // Mocked request
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/login")
                .body(objectMapper.writeValueAsString(mockedAuthRequest));

        // Mocked exchange
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // Mocked response
        mockResponse(HttpStatus.OK, "{\"jwt\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1Co-O-RC9nPM64b6Z_g496dKtOWNPo2mifQ6i5NWVdc\"}");

        Mockito.when(securityContextRepository.save(any(ServerWebExchange.class), any(SecurityContext.class))).thenReturn(Mono.empty());

        Mono<ResponseEntity<Object>> response = authController.login(mockedAuthRequest, exchange);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.OK)
                .verifyComplete();

        assertNull(mockedAuthRequest.getPassword());
        assertNull(mockedAuthRequest.getBase64OTActivationToken());
    }

    @Test
    void login_ReturnsUnauthorized_WhenBackendReturns200WithEmptyBody() throws Exception
    {
        AuthRequest mockedAuthRequest = new AuthRequest("test@email.com", "password1234", null);

        // Mocked request
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/login")
                .body(objectMapper.writeValueAsString(mockedAuthRequest));

        // Mocked exchange
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // Mocked response
        mockResponse(HttpStatus.OK, null);

        Mockito.when(securityContextRepository.save(any(ServerWebExchange.class), any(SecurityContext.class))).thenReturn(Mono.empty());

        Mono<ResponseEntity<Object>> response = authController.login(mockedAuthRequest, exchange);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verifyComplete();

        assertNull(mockedAuthRequest.getPassword());
        assertNull(mockedAuthRequest.getBase64OTActivationToken());
    }

    @Test
    void login_ReturnsBadRequestWithCustomMessage_WhenBackendReturnsValidBadRequest() throws Exception
    {
        AuthRequest mockedAuthRequest = new AuthRequest("test@email.com", "password1234", null);

        // Mocked request
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/login")
                .body(objectMapper.writeValueAsString(mockedAuthRequest));

        // Mocked exchange
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // Mocked response
        mockResponse(HttpStatus.BAD_REQUEST, "{\"status\": \"BAD REQUEST\", \"error\": \"QWERTY\"}");

        Mockito.when(securityContextRepository.save(any(ServerWebExchange.class), any(SecurityContext.class))).thenReturn(Mono.empty());

        Mono<ResponseEntity<Object>> response = authController.login(mockedAuthRequest, exchange);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse ->
                        nextResponse.getStatusCode() == HttpStatus.BAD_REQUEST
                        && nextResponse.getBody() instanceof String s
                        && "QWERTY".equals(s)
                )
                .verifyComplete();

        assertNull(mockedAuthRequest.getPassword());
        assertNull(mockedAuthRequest.getBase64OTActivationToken());
    }

    @Test
    void login_ReturnsUnauthorized_WhenBackendReturnsBadRequestWithEmptyBody() throws Exception
    {
        AuthRequest mockedAuthRequest = new AuthRequest("test@email.com", "password1234", null);

        // Mocked request
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/login")
                .body(objectMapper.writeValueAsString(mockedAuthRequest));

        // Mocked exchange
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // Mocked response
        mockResponse(HttpStatus.BAD_REQUEST, null);

        Mockito.when(securityContextRepository.save(any(ServerWebExchange.class), any(SecurityContext.class))).thenReturn(Mono.empty());

        Mono<ResponseEntity<Object>> response = authController.login(mockedAuthRequest, exchange);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verifyComplete();

        assertNull(mockedAuthRequest.getPassword());
        assertNull(mockedAuthRequest.getBase64OTActivationToken());
    }

    @Test
    void login_ReturnsUnauthorized_WhenBackendReturnsBadRequestWithInvalidBody() throws Exception
    {
        AuthRequest mockedAuthRequest = new AuthRequest("test@email.com", "password1234", null);

        // Mocked request
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/login")
                .body(objectMapper.writeValueAsString(mockedAuthRequest));

        // Mocked exchange
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // Mocked response
        mockResponse(HttpStatus.BAD_REQUEST, "{\"test\": \"test\"}");

        Mockito.when(securityContextRepository.save(any(ServerWebExchange.class), any(SecurityContext.class))).thenReturn(Mono.empty());

        Mono<ResponseEntity<Object>> response = authController.login(mockedAuthRequest, exchange);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verifyComplete();

        assertNull(mockedAuthRequest.getPassword());
        assertNull(mockedAuthRequest.getBase64OTActivationToken());
    }

    @Test
    void login_ReturnsUnauthorized_WhenBackendReturns200WithInvalidBody() throws Exception
    {
        AuthRequest mockedAuthRequest = new AuthRequest("test@email.com", "password1234", null);

        // Mocked request
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/login")
                .body(objectMapper.writeValueAsString(mockedAuthRequest));

        // Mocked exchange
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // Mocked response
        mockResponse(HttpStatus.OK, "{\"test\": \"test\"}");

        Mockito.when(securityContextRepository.save(any(ServerWebExchange.class), any(SecurityContext.class))).thenReturn(Mono.empty());

        Mono<ResponseEntity<Object>> response = authController.login(mockedAuthRequest, exchange);

        StepVerifier.create(response)
                .expectNextMatches(nextResponse -> nextResponse.getStatusCode() == HttpStatus.UNAUTHORIZED)
                .verifyComplete();

        assertNull(mockedAuthRequest.getPassword());
        assertNull(mockedAuthRequest.getBase64OTActivationToken());
    }
}
