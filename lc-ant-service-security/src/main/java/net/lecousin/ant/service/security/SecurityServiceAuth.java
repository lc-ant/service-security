package net.lecousin.ant.service.security;

import net.lecousin.ant.core.springboot.security.JwtResponse;
import net.lecousin.ant.core.springboot.security.JwtRequest;
import net.lecousin.ant.service.security.dto.AuthenticationWithAuthoritiesRequest;
import net.lecousin.ant.service.security.dto.AuthenticationWithSecretRequest;
import reactor.core.publisher.Mono;

public interface SecurityServiceAuth {

	Mono<JwtResponse> authenticateWithSecret(AuthenticationWithSecretRequest request);
	
	Mono<JwtResponse> authenticated(AuthenticationWithAuthoritiesRequest request);
	
	Mono<JwtResponse> renewToken(JwtRequest tokens);
	
	Mono<Void> closeToken(JwtRequest tokens);

}
