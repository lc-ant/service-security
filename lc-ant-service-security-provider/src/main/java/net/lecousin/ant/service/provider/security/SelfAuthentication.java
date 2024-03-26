package net.lecousin.ant.service.provider.security;

import java.util.List;
import java.util.function.Supplier;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.core.security.LcAntSecurity;
import net.lecousin.ant.core.springboot.security.ServiceAuthenticationProvider;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class SelfAuthentication implements ServiceAuthenticationProvider {
	
	private final SecurityServiceImplInternalAuth internalAuth;

	@Override
	public boolean canAuthenticate(String serviceName) {
		return SecurityServiceImpl.SERVICE_NAME.equals(serviceName);
	}
	
	@Override
	public <T> Mono<T> executeMonoAs(String serviceName, Supplier<Mono<T>> supplier) {
		if (!SecurityServiceImpl.SERVICE_NAME.equals(serviceName)) return Mono.error(new IllegalArgumentException());
		return Mono.defer(() -> {
			String token = internalAuth.selfAuthentication();
			Authentication auth = new UsernamePasswordAuthenticationToken(
				LcAntSecurity.SUBJECT_TYPE_SERVICE + ":" + SecurityServiceImpl.SERVICE_NAME,
	        	token,
	        	List.of()
	        );
			return supplier.get().contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
		});
	}
	
	@Override
	public <T> Flux<T> executeFluxAs(String serviceName, Supplier<Flux<T>> supplier) {
		if (!SecurityServiceImpl.SERVICE_NAME.equals(serviceName)) return Flux.error(new IllegalArgumentException());
		return Flux.defer(() -> {
			String token = internalAuth.selfAuthentication();
			Authentication auth = new UsernamePasswordAuthenticationToken(
				LcAntSecurity.SUBJECT_TYPE_SERVICE + ":" + SecurityServiceImpl.SERVICE_NAME,
	        	token,
	        	List.of()
	        );
			return supplier.get().contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
		});
	}
	
}
