package net.lecousin.ant.service.provider.security;

import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.connector.database.DatabaseConnector;
import net.lecousin.ant.connector.database.request.PatchElement;
import net.lecousin.ant.core.condition.Condition;
import net.lecousin.ant.core.springboot.connector.ConnectorService;
import net.lecousin.ant.core.springboot.security.SecurityConstants;
import net.lecousin.ant.core.springboot.security.SecurityUtils;
import net.lecousin.ant.core.utils.RandomUtils;
import net.lecousin.ant.service.provider.security.db.SecretEntity;
import net.lecousin.ant.service.provider.security.db.SubjectTypeEntity;
import net.lecousin.ant.service.security.SecurityServiceSecrets;
import reactor.core.publisher.Mono;

@Service("securityServiceProviderSecrets")
@Primary
@RequiredArgsConstructor
public class SecurityServiceImplSecrets implements SecurityServiceSecrets {

	private final ConnectorService connectorService;
	private final SecureRandom random;
	
	@Override
	public Mono<Void> setSecret(Optional<String> tenantId, String subjectType, String subjectId, String secret) {
		return SecurityUtils.getAuthentication()
			.flatMap(auth -> {
				if (SecurityConstants.SUBJECT_TYPE_SERVICE.equals(subjectType)) {
					return SecurityUtils.requiresAuthority(auth, SecurityConstants.AUTHORITY_ROOT);
				}
				return connectorService.getConnector(DatabaseConnector.class)
					.flatMap(db -> db.findById(SubjectTypeEntity.class, subjectType))
					.filter(entity -> SecurityUtils.isSubject(auth, SecurityConstants.SUBJECT_TYPE_SERVICE, entity.getAuthorizedService()))
					.switchIfEmpty(Mono.error(new AccessDeniedException("subjectType " + subjectType)))
					.then();
			})
			.then(Mono.defer(() -> {
				return connectorService.getConnector(DatabaseConnector.class)
					.flatMap(db ->
						db.find(SecretEntity.class)
						.where(Condition.and(
							Condition.field("tenantId").is(tenantId.orElse(null)),
							Condition.field("subjectType").is(subjectType),
							Condition.field("subjectId").is(subjectId)
						))
						.executeSingle()
						.switchIfEmpty(Mono.fromSupplier(() -> SecretEntity.builder()
							.tenantId(tenantId)
							.subjectType(subjectType)
							.subjectId(subjectId)
							.build()
						))
						.flatMap(db::save)
					).then();
			}));
	}
	
	@Override
	public Mono<String> generateNewSecret(Optional<String> tenantId, String subjectType, String subjectId) {
		return SecurityUtils.getAuthentication()
			.flatMap(auth -> {
				if (SecurityConstants.SUBJECT_TYPE_SERVICE.equals(subjectType)) {
					return SecurityUtils.requiresAuthority(auth, SecurityConstants.AUTHORITY_ROOT);
				}
				return connectorService.getConnector(DatabaseConnector.class)
					.flatMap(db -> db.findById(SubjectTypeEntity.class, subjectType))
					.filter(entity -> SecurityUtils.isSubject(auth, SecurityConstants.SUBJECT_TYPE_SERVICE, entity.getAuthorizedService()))
					.switchIfEmpty(Mono.error(new AccessDeniedException("subjectType " + subjectType)))
					.then();
			})
			.then(Mono.defer(() -> {
				return connectorService.getConnector(DatabaseConnector.class)
					.flatMap(db -> {
						String newSecret = generateSecret();
						return db.patch(
							SecretEntity.class,
							List.of(PatchElement.set("secret", hashSecret(newSecret))),
							Condition.and(
								Condition.field("tenantId").is(tenantId.orElse(null)),
								Condition.field("subjectType").is(subjectType),
								Condition.field("subjectId").is(subjectId)
							)
						).then(Mono.just(newSecret));
					});
			}));
	}
	
	public Mono<List<String>> validateSecret(Optional<String> tenantId, String subjectType, String subjectId, String secret) {
		return connectorService.getConnector(DatabaseConnector.class)
		.flatMap(db ->
			db.find(SecretEntity.class)
			.where(Condition.and(
				Condition.field("tenantId").is(tenantId.orElse(null)),
				Condition.field("subjectType").is(subjectType),
				Condition.field("subjectId").is(subjectId),
				Condition.field("secret").is(hashSecret(secret))
			))
			.executeSingle()
			.map(found -> found.getPermissions())
		);
	}
	
	private String hashSecret(String secret) {
		return DigestUtils.sha256Hex(secret);
	}
	
	private String generateSecret() {
		return RandomUtils.generateAlphaNumericWithSymbols(random, 16);
	}
	
}
