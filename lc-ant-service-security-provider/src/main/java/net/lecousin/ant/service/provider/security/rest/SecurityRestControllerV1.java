package net.lecousin.ant.service.provider.security.rest;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.service.security.SecurityService;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import net.lecousin.ant.service.security.SecurityServiceSecrets;

@Service("securityServiceRestControllerV1")
@RequiredArgsConstructor
public class SecurityRestControllerV1 implements SecurityService {

	private final SecurityRestControllerV1Secrets secrets;
	private final SecurityRestControllerV1InternalAuth internalAuth;
	
	@Override
	public SecurityServiceSecrets secrets() {
		return secrets;
	}
	
	@Override
	public SecurityServiceAuth internalAuth() {
		return internalAuth;
	}
	
}
