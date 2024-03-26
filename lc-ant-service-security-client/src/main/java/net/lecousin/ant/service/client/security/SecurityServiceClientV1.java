package net.lecousin.ant.service.client.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import net.lecousin.ant.service.security.SecurityService;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import net.lecousin.ant.service.security.SecurityServiceSecrets;

@Service("securityServiceRestClientV1")
public class SecurityServiceClientV1 implements SecurityService {

	private @Autowired @Lazy SecurityServiceClientV1Secrets secrets;
	private @Autowired @Lazy  SecurityServiceClientV1InternalAuth internalAuth;
	
	@Override
	public SecurityServiceSecrets secrets() {
		return secrets;
	}
	
	@Override
	public SecurityServiceAuth internalAuth() {
		return internalAuth;
	}
	
}
