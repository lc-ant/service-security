package net.lecousin.ant.service.provider.security.rest;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.core.springboot.security.JwtRequest;
import net.lecousin.ant.core.springboot.security.JwtResponse;
import net.lecousin.ant.service.provider.security.SecurityServiceImplInternalAuth;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import net.lecousin.ant.service.security.dto.AuthenticationWithAuthoritiesRequest;
import net.lecousin.ant.service.security.dto.AuthenticationWithSecretRequest;
import reactor.core.publisher.Mono;

@RestController("securityServiceRestControllerV1InternalAuth")
@RequestMapping("/api/security/v1/auth/internal")
@RequiredArgsConstructor
public class SecurityRestControllerV1InternalAuth implements SecurityServiceAuth {

	private final SecurityServiceImplInternalAuth service;
	
	@PostMapping("authenticate")
	@Override
	public Mono<JwtResponse> authenticateWithSecret(@RequestBody AuthenticationWithSecretRequest request) {
		return service.authenticateWithSecret(request);
	}
	
	@PostMapping("authenticated")
	@Override
	public Mono<JwtResponse> authenticated(@RequestBody AuthenticationWithAuthoritiesRequest request) {
		return service.authenticated(request);
	}
	
	@PostMapping("renew")
	@Override
	public Mono<JwtResponse> renewToken(@RequestBody JwtRequest tokens) {
		return service.renewToken(tokens);
	}
	
	@PostMapping("close")
	@Override
	public Mono<Void> closeToken(@RequestBody JwtRequest tokens) {
		return service.closeToken(tokens);
	}
	
}
