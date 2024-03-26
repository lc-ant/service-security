package net.lecousin.ant.service.provider.security;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.lecousin.ant.connector.database.DatabaseConnector;
import net.lecousin.ant.core.security.LcAntSecurity;
import net.lecousin.ant.core.security.NodePermissionDeclaration;
import net.lecousin.ant.core.security.PermissionDeclaration;
import net.lecousin.ant.core.security.Root;
import net.lecousin.ant.core.springboot.connector.ConnectorService;
import net.lecousin.ant.core.springboot.service.provider.LcAntServiceProvider;
import net.lecousin.ant.service.provider.security.db.SubjectTypeEntity;
import net.lecousin.ant.service.security.SecurityService;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import net.lecousin.ant.service.security.SecurityServiceSecrets;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service("securityServiceProvider")
@Primary
@RequiredArgsConstructor
@Slf4j
public class SecurityServiceImpl implements SecurityService, LcAntServiceProvider {

	public static final String SERVICE_NAME = "security";
	
	private final SecurityServiceImplSecrets secrets;
	private final SecurityServiceImplInternalAuth internalAuth;
	private final ConnectorService connectorService;
	
	@Override
	public String getServiceName() {
		return SERVICE_NAME;
	}
	
	@Override
	public List<PermissionDeclaration> getServicePermissions() {
		return Collections.emptyList();
	}
	
	@Override
	public List<NodePermissionDeclaration> getServiceNodePermissions() {
		return Collections.emptyList();
	}

	@Override
	public List<Object> getDependencies() {
		return List.of();
	}
	
	@Override
	public SecurityServiceSecrets secrets() {
		return secrets;
	}
	
	@Override
	public SecurityServiceAuth internalAuth() {
		return internalAuth;
	}
	
	@Override
	public Mono<Void> init(ConfigurableApplicationContext applicationContext) {
		String envValue = (String) applicationContext.getEnvironment().getSystemEnvironment().get("INIT_SERVICE_SECRET");
		Mono<Void> initServicesSecrets;
		if (envValue != null) {
			List<Mono<Void>> monos = new LinkedList<>();
			String[] services = envValue.split(";");
			for (String serviceSecret : services) {
				int i = serviceSecret.indexOf(':');
				if (i <= 0) continue;
				String serviceName = serviceSecret.substring(0, i);
				String secret = serviceSecret.substring(i + 1);
				log.info("Startup: create initial secret for service {}", serviceName);
				monos.add(
					secrets.setSecret(Optional.empty(), LcAntSecurity.SUBJECT_TYPE_SERVICE, serviceName, secret)
					.contextWrite(ReactiveSecurityContextHolder.withAuthentication(new UsernamePasswordAuthenticationToken("", "", List.of(new SimpleGrantedAuthority(Root.AUTHORITY)))))
					.checkpoint("Security service application ready: Create initial secret for service " + serviceName)
				);
			}
			initServicesSecrets = Flux.fromIterable(monos).flatMap(mono -> mono).then();
		} else {
			initServicesSecrets = Mono.empty();
		}
		envValue = (String) applicationContext.getEnvironment().getSystemEnvironment().get("INIT_SUBJECT_TYPE_SERVICE");
		Mono<Void> initSubjectTypeServices;
		if (envValue != null) {
			List<Mono<Void>> monos = new LinkedList<>();
			String[] services = envValue.split(";");
			for (String service : services) {
				int i = service.indexOf(':');
				if (i <= 0) continue;
				String subjectType = service.substring(0, i);
				String serviceName = service.substring(i + 1);
				log.info("Startup: set service {} allowed to authenticate subjet type {}", serviceName, subjectType);
				monos.add(
					setAllowedServiceForSubjectType(serviceName, subjectType)
					.checkpoint("Security service application ready: Set service " + serviceName + " allowed to authenticate subject type " + subjectType)
				);
			}
			initSubjectTypeServices = Flux.fromIterable(monos).flatMap(mono -> mono).then();
		} else {
			initSubjectTypeServices = Mono.empty();
		}
		return initServicesSecrets.then(initSubjectTypeServices);
	}
	
	private Mono<Void> setAllowedServiceForSubjectType(String serviceName, String subjectType) {
		return connectorService.getConnector(DatabaseConnector.class)
		.flatMap(db ->
			db.findById(SubjectTypeEntity.class, subjectType)
			.flatMap(entity -> {
				if (entity.getAuthorizedService().equals(serviceName)) return Mono.just(entity);
				entity.setAuthorizedService(serviceName);
				return db.update(entity);
			})
			.switchIfEmpty(Mono.defer(() -> {
				SubjectTypeEntity entity = new SubjectTypeEntity();
				entity.setSubjectType(subjectType);
				entity.setAuthorizedService(serviceName);
				return db.create(entity);
			}))
		).then();
	}
	
	@Override
	public Mono<Void> stop(ConfigurableApplicationContext applicationContext) {
		return Mono.empty();
	}
	
}
