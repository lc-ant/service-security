package net.lecousin.ant.service.provider.security.rest;

import java.util.Optional;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.service.provider.security.SecurityServiceImplSecrets;
import net.lecousin.ant.service.security.SecurityServiceSecrets;
import reactor.core.publisher.Mono;

@RestController("securityServiceRestControllerV1Secrets")
@RequestMapping("/api/security/v1/secrets")
@RequiredArgsConstructor
public class SecurityRestControllerV1Secrets implements SecurityServiceSecrets {

	private final SecurityServiceImplSecrets service;
	
	@PostMapping("/{subjectType}/{subjectId}")
	@Override
	public Mono<Void> setSecret(
		@RequestParam(value = "tenantId", required = false) Optional<String> tenantId,
		@PathVariable("subjectType") String subjectType,
		@PathVariable("subjectId") String subjectId,
		@RequestBody String secret) {
		return service.setSecret(tenantId, subjectType, subjectId, secret);
	}

	@PutMapping("/{subjectType}/{subjectId}")
	@Override
	public Mono<String> generateNewSecret(
		@RequestParam(value = "tenantId", required = false) Optional<String> tenantId,
		@PathVariable("subjectType") String subjectType,
		@PathVariable("subjectId") String subjectId) {
		return service.generateNewSecret(tenantId, subjectType, subjectId);
	}
	
}
