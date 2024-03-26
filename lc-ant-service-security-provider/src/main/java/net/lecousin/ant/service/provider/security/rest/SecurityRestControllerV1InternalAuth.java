package net.lecousin.ant.service.provider.security.rest;

import java.util.List;
import java.util.Optional;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.core.springboot.security.JwtResponse;
import net.lecousin.ant.core.springboot.security.Permission;
import net.lecousin.ant.service.provider.security.SecurityServiceImplInternalAuth;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import reactor.core.publisher.Mono;

@RestController("securityServiceRestControllerV1InternalAuth")
@RequestMapping("/api/security/v1/auth/internal")
@RequiredArgsConstructor
public class SecurityRestControllerV1InternalAuth implements SecurityServiceAuth {

	private final SecurityServiceImplInternalAuth service;
	
	@PostMapping("authenticate/{subjectType}/{subjectId}/{tenantId}")
	@Override
	public Mono<JwtResponse> authenticateWithSecret(
		@PathVariable(value = "tenantId", required = false) Optional<String> tenantId,
		@PathVariable("subjectType") String subjectType,
		@PathVariable("subjectId") String subjectId,
		@RequestBody String secret) {
		return service.authenticateWithSecret(tenantId, subjectType, subjectId, secret);
	}
	
	@PostMapping("authenticated/{subjectType}/{subjectId}/{tenantId}")
	@Override
	public Mono<JwtResponse> authenticated(
		@PathVariable(value = "tenantId", required = false) Optional<String> tenantId,
		@PathVariable("subjectType") String subjectType,
		@PathVariable("subjectId") String subjectId,
		@RequestBody List<Permission> permissions) {
		return service.authenticated(tenantId, subjectType, subjectId, permissions);
	}
	
	@PostMapping("renew")
	@Override
	public Mono<JwtResponse> renewToken(@RequestBody String renewToken) {
		return service.renewToken(renewToken);
	}
	
	@PostMapping("close")
	@Override
	public Mono<Void> closeToken(@RequestBody String renewToken) {
		return service.closeToken(renewToken);
	}
	
}
