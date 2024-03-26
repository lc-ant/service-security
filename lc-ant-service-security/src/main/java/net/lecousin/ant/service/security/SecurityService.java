package net.lecousin.ant.service.security;

public interface SecurityService {
	
	SecurityServiceSecrets secrets();
	
	SecurityServiceAuth internalAuth();
	
}
