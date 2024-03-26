package net.lecousin.ant.service.client.security;

import java.util.List;
import java.util.Optional;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

import net.lecousin.ant.core.springboot.security.JwtResponse;
import net.lecousin.ant.core.springboot.security.Permission;
import net.lecousin.ant.core.springboot.service.client.LcAntServiceClient;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import reactor.core.publisher.Mono;

@HttpExchange("/api/security/v1/auth/internal")
@LcAntServiceClient(service = "${lc-ant.services.security:security-service}", qualifier = "securityServiceRestClientV1InternalAuth")
public interface SecurityServiceClientV1InternalAuth extends SecurityServiceAuth {

	@PostExchange("authenticate/{subjectType}/{subjectId}/{tenantId}")
	@Override
	Mono<JwtResponse> authenticateWithSecret(
		@PathVariable(value = "tenantId", required = false) Optional<String> tenantId,
		@PathVariable("subjectType") String subjectType,
		@PathVariable("subjectId") String subjectId,
		@RequestBody String secret);
	
	@PostExchange("authenticated/{subjectType}/{subjectId}/{tenantId}")
	@Override
	Mono<JwtResponse> authenticated(
		@PathVariable(value = "tenantId", required = false) Optional<String> tenantId,
		@PathVariable("subjectType") String subjectType,
		@PathVariable("subjectId") String subjectId,
		@RequestBody List<Permission> permissions);
	
	@PostExchange("renew")
	@Override
	Mono<JwtResponse> renewToken(@RequestBody String renewToken);
	
	@PostExchange("close")
	@Override
	Mono<Void> closeToken(@RequestBody String renewToken);

}
