package net.lecousin.ant.service.security;

import java.util.Optional;

import reactor.core.publisher.Mono;

public interface SecurityServiceSecrets {

	Mono<Void> setSecret(Optional<String> tenantId, String subjectType, String subjectId, String secret);
	
	Mono<String> generateNewSecret(Optional<String> tenantId, String subjectType, String subjectId);
	
}
