package twoauth.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication // TODO (exclude = { ReactiveUserDetailsServiceAutoConfiguration.class })
public class TwoAuthApiGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(TwoAuthApiGatewayApplication.class, args);
	}

}
