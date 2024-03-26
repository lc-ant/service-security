package net.lecousin.ant.service.provider.security;

import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.service.security.SecurityService;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import net.lecousin.ant.service.security.SecurityServiceSecrets;

@Service("securityServiceProvider")
@Primary
@RequiredArgsConstructor
public class SecurityServiceImpl implements SecurityService {

	private final SecurityServiceImplSecrets secrets;
	private final SecurityServiceImplInternalAuth internalAuth;
	
	@Override
	public SecurityServiceSecrets secrets() {
		return secrets;
	}
	
	@Override
	public SecurityServiceAuth internalAuth() {
		return internalAuth;
	}
	
}
