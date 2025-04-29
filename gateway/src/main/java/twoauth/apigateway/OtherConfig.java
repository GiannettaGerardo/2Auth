package twoauth.apigateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
class OtherConfig
{
    @Bean
    WebClient webClient() {
        return WebClient.builder().build();
    }
}
