package net.lecousin.ant.service.client.security;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.service.security.SecurityService;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import net.lecousin.ant.service.security.SecurityServiceSecrets;

@Service("securityServiceRestClientV1")
@RequiredArgsConstructor
public class SecurityServiceClientV1 implements SecurityService {

	private final SecurityServiceClientV1Secrets secrets;
	private final SecurityServiceClientV1InternalAuth internalAuth;
	
	@Override
	public SecurityServiceSecrets secrets() {
		return secrets;
	}
	
	@Override
	public SecurityServiceAuth internalAuth() {
		return internalAuth;
	}
	
}
