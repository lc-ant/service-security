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
import net.lecousin.ant.core.expression.impl.ConditionAnd;
import net.lecousin.ant.core.patch.Patch;
import net.lecousin.ant.core.security.LcAntSecurity;
import net.lecousin.ant.core.security.Root;
import net.lecousin.ant.core.springboot.connector.ConnectorService;
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
				if (LcAntSecurity.SUBJECT_TYPE_SERVICE.equals(subjectType)) {
					if (auth.getAuthorities().stream().anyMatch(g -> Root.AUTHORITY.equals(g.getAuthority()))) return Mono.empty();
					return Mono.error(new AccessDeniedException("Needs root authority"));
				}
				return connectorService.getConnector(DatabaseConnector.class)
					.flatMap(db -> db.findById(SubjectTypeEntity.class, subjectType))
					.filter(entity -> SecurityUtils.isSubject(auth, LcAntSecurity.SUBJECT_TYPE_SERVICE, entity.getAuthorizedService()))
					.switchIfEmpty(Mono.error(new AccessDeniedException("subjectType " + subjectType)))
					.then();
			})
			.then(Mono.defer(() -> {
				return connectorService.getConnector(DatabaseConnector.class)
					.flatMap(db ->
						db.find(SecretEntity.class)
						.where(new ConditionAnd(
							SecretEntity.FIELD_TENANT_ID.is(tenantId),
							SecretEntity.FIELD_SUBJECT_TYPE.is(subjectType),
							SecretEntity.FIELD_SUBJECT_ID.is(subjectId)
						))
						.executeSingle()
						.switchIfEmpty(Mono.fromSupplier(() -> SecretEntity.builder()
							.tenantId(tenantId)
							.subjectType(subjectType)
							.subjectId(subjectId)
							.build()
						))
						.doOnNext(entity -> entity.setSecret(hashSecret(secret)))
						.flatMap(db::save)
					).then();
			}));
	}
	
	@Override
	public Mono<String> generateNewSecret(Optional<String> tenantId, String subjectType, String subjectId) {
		return SecurityUtils.getAuthentication()
			.flatMap(auth -> {
				if (LcAntSecurity.SUBJECT_TYPE_SERVICE.equals(subjectType)) {
					if (auth.getAuthorities().stream().anyMatch(g -> Root.AUTHORITY.equals(g.getAuthority()))) return Mono.empty();
					return Mono.error(new AccessDeniedException("Needs root authority"));
				}
				return connectorService.getConnector(DatabaseConnector.class)
					.flatMap(db -> db.findById(SubjectTypeEntity.class, subjectType))
					.filter(entity -> SecurityUtils.isSubject(auth, LcAntSecurity.SUBJECT_TYPE_SERVICE, entity.getAuthorizedService()))
					.switchIfEmpty(Mono.error(new AccessDeniedException("subjectType " + subjectType)))
					.then();
			})
			.then(Mono.defer(() -> {
				return connectorService.getConnector(DatabaseConnector.class)
					.flatMap(db -> {
						String newSecret = generateSecret();
						return db.patchOne(
							SecretEntity.class,
							new ConditionAnd(
								SecretEntity.FIELD_TENANT_ID.is(tenantId),
								SecretEntity.FIELD_SUBJECT_TYPE.is(subjectType),
								SecretEntity.FIELD_SUBJECT_ID.is(subjectId)
							),
							List.of(Patch.field(SecretEntity.FIELD_SECRET).set(hashSecret(newSecret)))
						).then(Mono.just(newSecret));
					});
			}));
	}
	
	public Mono<List<String>> validateSecret(Optional<String> tenantId, String subjectType, String subjectId, String secret) {
		return connectorService.getConnector(DatabaseConnector.class)
		.flatMap(db ->
			db.find(SecretEntity.class)
			.where(new ConditionAnd(
				SecretEntity.FIELD_TENANT_ID.is(tenantId),
				SecretEntity.FIELD_SUBJECT_TYPE.is(subjectType),
				SecretEntity.FIELD_SUBJECT_ID.is(subjectId),
				SecretEntity.FIELD_SECRET.is(hashSecret(secret))
			))
			.executeSingle()
			.map(SecretEntity::getAuthorities)
		);
	}
	
	private String hashSecret(String secret) {
		return DigestUtils.sha256Hex(secret);
	}
	
	private String generateSecret() {
		return RandomUtils.generateAlphaNumericWithSymbols(random, 16);
	}
	
}
