package net.lecousin.ant.service.client.security;

import java.util.Optional;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;
import org.springframework.web.service.annotation.PutExchange;

import net.lecousin.ant.core.springboot.service.client.LcAntServiceClient;
import net.lecousin.ant.service.security.SecurityServiceSecrets;
import reactor.core.publisher.Mono;

@HttpExchange("/api/security/v1/secrets")
@LcAntServiceClient(serviceName = "security", serviceUrl = "${lc-ant.services.security:security-service}", qualifier = "securityServiceRestClientV1Secrets")
public interface SecurityServiceClientV1Secrets extends SecurityServiceSecrets {

	@PostExchange("/{subjectType}/{subjectId}")
	@Override
	Mono<Void> setSecret(
		@RequestParam(value = "tenantId", required = false) Optional<String> tenantId,
		@PathVariable("subjectType") String subjectType,
		@PathVariable("subjectId") String subjectId,
		@RequestBody String secret);

	@PutExchange("/{subjectType}/{subjectId}")
	@Override
	Mono<String> generateNewSecret(
		@RequestParam(value = "tenantId", required = false) Optional<String> tenantId,
		@PathVariable("subjectType") String subjectType,
		@PathVariable("subjectId") String subjectId);

}
