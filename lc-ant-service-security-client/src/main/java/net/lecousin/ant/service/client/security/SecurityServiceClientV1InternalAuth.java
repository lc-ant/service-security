package net.lecousin.ant.service.client.security;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

import net.lecousin.ant.core.springboot.security.JwtRequest;
import net.lecousin.ant.core.springboot.security.JwtResponse;
import net.lecousin.ant.core.springboot.service.client.LcAntServiceClient;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import net.lecousin.ant.service.security.dto.AuthenticationWithAuthoritiesRequest;
import net.lecousin.ant.service.security.dto.AuthenticationWithSecretRequest;
import reactor.core.publisher.Mono;

@HttpExchange("/api/security/v1/auth/internal")
@LcAntServiceClient(serviceName = "security", serviceUrl = "${lc-ant.services.security:security-service}", qualifier = "securityServiceRestClientV1InternalAuth")
public interface SecurityServiceClientV1InternalAuth extends SecurityServiceAuth {

	@PostExchange("authenticate")
	@Override
	Mono<JwtResponse> authenticateWithSecret(@RequestBody AuthenticationWithSecretRequest request);
	
	@PostExchange("authenticated")
	@Override
	Mono<JwtResponse> authenticated(@RequestBody AuthenticationWithAuthoritiesRequest request);
	
	@PostExchange("renew")
	@Override
	Mono<JwtResponse> renewToken(@RequestBody JwtRequest tokens);
	
	@PostExchange("close")
	@Override
	Mono<Void> closeToken(@RequestBody JwtRequest tokens);

}
