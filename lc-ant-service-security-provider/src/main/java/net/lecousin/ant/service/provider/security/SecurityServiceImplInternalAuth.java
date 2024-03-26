package net.lecousin.ant.service.provider.security;

import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.connector.database.DatabaseConnector;
import net.lecousin.ant.core.api.exceptions.UnauthorizedException;
import net.lecousin.ant.core.expression.impl.ConditionAnd;
import net.lecousin.ant.core.security.LcAntSecurity;
import net.lecousin.ant.core.security.Root;
import net.lecousin.ant.core.security.TenantPermission;
import net.lecousin.ant.core.springboot.aop.Valid;
import net.lecousin.ant.core.springboot.connector.ConnectorService;
import net.lecousin.ant.core.springboot.security.JwtRequest;
import net.lecousin.ant.core.springboot.security.JwtResponse;
import net.lecousin.ant.core.springboot.security.SecurityUtils;
import net.lecousin.ant.core.validation.ValidationContext;
import net.lecousin.ant.service.jobcontrol.annotations.RecurringTask;
import net.lecousin.ant.service.provider.security.db.RenewalEntity;
import net.lecousin.ant.service.provider.security.db.SubjectTypeEntity;
import net.lecousin.ant.service.provider.security.exceptions.SubjectTypeNotAllowedException;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import net.lecousin.ant.service.security.dto.AuthenticationWithAuthoritiesRequest;
import net.lecousin.ant.service.security.dto.AuthenticationWithSecretRequest;
import reactor.core.publisher.Mono;

@Service("securityServiceProviderInternalAuth")
@Primary
@RequiredArgsConstructor
public class SecurityServiceImplInternalAuth implements SecurityServiceAuth, InitializingBean {

	private final SecurityServiceImplSecrets secretsService;
	private final ConnectorService connectorService;
	private final SecurityServiceProperties properties;
	private final SecureRandom random;
	
	@Value("${lc-ant.security.public-key}")
	private String publicKeyBase64;
	
	private Algorithm algo;
	private JWTVerifier verifier;
	
	@Override
	public void afterPropertiesSet() throws Exception {
		PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(properties.getPrivateKey()));
		RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpecPrivate);
		X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64));
		RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpecPublic);
		algo = Algorithm.RSA512(publicKey, privateKey);
		verifier = JWT.require(algo).build();
	}
	
	@Override
	public Mono<JwtResponse> authenticateWithSecret(@Valid(ValidationContext.CREATION) AuthenticationWithSecretRequest request) {
		return secretsService.validateSecret(request.getTenantId(), request.getSubjectType(), request.getSubjectId(), request.getSecret())
			.switchIfEmpty(Mono.error(new UnauthorizedException()))
			.flatMap(authorities -> generateTokens(
				request.getTenantId(), request.getSubjectType(), request.getSubjectId(),
				authorities,
				false,
				request.getTokenDuration(), request.getRenewTokenDuration()));
	}
	
	@Override
	public Mono<JwtResponse> authenticated(@Valid(ValidationContext.CREATION) AuthenticationWithAuthoritiesRequest request) {
		return SecurityUtils.getAuthentication()
			.flatMap(auth -> {
				if (LcAntSecurity.SUBJECT_TYPE_SERVICE.equals(request.getSubjectType()))
					return Mono.error(new SubjectTypeNotAllowedException(LcAntSecurity.SUBJECT_TYPE_SERVICE));
				return connectorService.getConnector(DatabaseConnector.class)
				.flatMap(db -> db.findById(SubjectTypeEntity.class, request.getSubjectType()))
				.filter(entity -> SecurityUtils.isSubject(auth, LcAntSecurity.SUBJECT_TYPE_SERVICE, entity.getAuthorizedService()))
				.switchIfEmpty(Mono.error(new AccessDeniedException("subjectType " + request.getSubjectType())))
				.flatMap(r -> generateTokens(request.getTenantId(), request.getSubjectType(), request.getSubjectId(), request.getAuthorities(), request.isRoot(), request.getTokenDuration(), request.getRenewTokenDuration()));
			});
	}
	
	@Override
	public Mono<JwtResponse> renewToken(JwtRequest tokens) {
		return Mono.defer(() -> {
			DecodedJWT refresh = JWT.decode(tokens.getRefreshToken());
			try {
				verifier.verify(refresh);
			} catch (Exception e) {
				return Mono.error(new UnauthorizedException());
			}
			DecodedJWT access = JWT.decode(tokens.getAccessToken());
			
			String renewalId = refresh.getClaim("i").asString();
			String renewalSubject = refresh.getSubject();
			String accessSubject = access.getSubject();
			if (!renewalSubject.equals(accessSubject))
				return Mono.error(new AccessDeniedException("Invalid token"));
	
			Duration accessDuration = Duration.between(access.getIssuedAtAsInstant(), access.getExpiresAtAsInstant());
			List<String> authorities = access.getClaim(LcAntSecurity.CLAIM_AUTHORITIES).asList(String.class);
			
			return connectorService.getConnector(DatabaseConnector.class)
			.flatMap(db ->
				db.find(RenewalEntity.class).where(RenewalEntity.FIELD_ID.is(renewalId)).executeSingle()
				.switchIfEmpty(Mono.error(new AccessDeniedException("Invalid token")))
				.flatMap(renewal -> {
					if (!renewal.getSubject().equals(renewalSubject))
						return Mono.error(new AccessDeniedException("Invalid token"));
					if (!renewal.getAccessToken().equals(tokens.getAccessToken()))
						return Mono.error(new AccessDeniedException("Invalid token"));
					Duration renewDuration = Duration.between(renewal.getIssuedAt(), renewal.getExpiresAt());
					return db.delete(RenewalEntity.class, RenewalEntity.FIELD_ID.is(renewalId))
					.then(generateTokens(db, accessSubject, new HashSet<>(authorities), accessDuration, renewDuration));
				})
			);
		});
	}
	
	@Override
	public Mono<Void> closeToken(JwtRequest tokens) {
		return Mono.defer(() -> {
			DecodedJWT refresh = JWT.decode(tokens.getRefreshToken());
			try {
				verifier.verify(refresh);
			} catch (Exception e) {
				return Mono.error(new UnauthorizedException());
			}
			String renewalId = refresh.getClaim("i").asString();

			return connectorService.getConnector(DatabaseConnector.class)
			.flatMap(db -> db.delete(RenewalEntity.class, new ConditionAnd(
				RenewalEntity.FIELD_ID.is(renewalId),
				RenewalEntity.FIELD_ACCESS_TOKEN.is(tokens.getAccessToken())
			)));
		});
	}
	
	String selfAuthentication() {
		return JWT.create()
		.withSubject(LcAntSecurity.SUBJECT_TYPE_SERVICE + ":" + SecurityServiceImpl.SERVICE_NAME)
		.withIssuedAt(Instant.now())
		.withExpiresAt(Instant.now().plus(Duration.ofMinutes(10)))
		.withClaim("r", random.nextLong())
		.withClaim(LcAntSecurity.CLAIM_AUTHORITIES, List.of())
		.sign(algo);
	}
	
	private Mono<JwtResponse> generateTokens(Optional<String> tenantId, String subjectType, String subjectId, List<String> authorities, boolean isRoot, Duration tokenDuration, Duration renewTokenDuration) {
		return Mono.defer(() -> {
			String subject = subjectType + ':' + subjectId;
			Set<String> finalAuthorities = new HashSet<>(authorities);
			if (tenantId.isPresent()) finalAuthorities.add(new TenantPermission(tenantId.get()).toAuthority());
			if (isRoot) finalAuthorities.add(Root.AUTHORITY);
			return connectorService.getConnector(DatabaseConnector.class)
			.flatMap(db -> generateTokens(db, subject, finalAuthorities, tokenDuration, renewTokenDuration));
		});
	}
	
	private Mono<JwtResponse> generateTokens(DatabaseConnector db, String subject, Set<String> authorities, Duration accessTokenDuration, Duration renewTokenDuration) {
		return Mono.defer(() -> {
			Instant issuedAt = Instant.now();
			Instant accessTokenExpiresAt = issuedAt.plus(accessTokenDuration);
			Instant refreshTokenExpiresAt = issuedAt.plus(renewTokenDuration);
			String accessToken = generateAccessToken(subject, authorities, issuedAt, accessTokenExpiresAt);
			
			RenewalEntity renewal = RenewalEntity.builder()
				.subject(subject)
				.issuedAt(issuedAt)
				.expiresAt(refreshTokenExpiresAt)
				.accessToken(accessToken)
				.build();
			
			return db.create(renewal)
			.map(entity -> generateRefreshToken(entity))
			.map(refreshToken -> new JwtResponse(accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt));
		});
	}
	
	private String generateAccessToken(String subject, Set<String> authorities, Instant issuedAt, Instant expiresAt) {
		return JWT.create()
			.withSubject(subject)
			.withIssuedAt(issuedAt)
			.withExpiresAt(expiresAt)
			.withClaim("r", random.nextLong())
			.withClaim(LcAntSecurity.CLAIM_AUTHORITIES, new ArrayList<>(authorities))
			.sign(algo);
	}
	
	private String generateRefreshToken(RenewalEntity renewal) {
		return JWT.create()
			.withSubject(renewal.getSubject())
			.withIssuedAt(renewal.getIssuedAt())
			.withExpiresAt(renewal.getExpiresAt())
			.withClaim("r", random.nextLong())
			.withClaim("i", renewal.getId())
			.sign(algo);
	}
	
	@RecurringTask(serviceName = SecurityServiceImpl.SERVICE_NAME, initialDelayMillis = 60L * 1000, intervalMillis = 30L * 60 * 1000, diplayNameNamespace = "service-security", displayNameKey = "task-clean-renewal-entities")
	public Mono<Void> cleanRenewalEntities() {
		return connectorService.getConnector(DatabaseConnector.class)
		.flatMap(db -> db.delete(RenewalEntity.class, RenewalEntity.FIELD_EXPIRES_AT.lessThan(Instant.now())));
	}
}
