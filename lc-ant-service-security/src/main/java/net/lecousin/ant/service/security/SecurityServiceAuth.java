package net.lecousin.ant.service.security;

import java.util.List;
import java.util.Optional;

import net.lecousin.ant.core.springboot.security.JwtResponse;
import net.lecousin.ant.core.springboot.security.Permission;
import reactor.core.publisher.Mono;

public interface SecurityServiceAuth {

	Mono<JwtResponse> authenticateWithSecret(Optional<String> tenantId, String subjectType, String subjectId, String secret);
	
	Mono<JwtResponse> authenticated(Optional<String> tenantId, String subjectType, String subjectId, List<Permission> permissions);
	
	Mono<JwtResponse> renewToken(String renewToken);
	
	Mono<Void> closeToken(String renewToken);

}
