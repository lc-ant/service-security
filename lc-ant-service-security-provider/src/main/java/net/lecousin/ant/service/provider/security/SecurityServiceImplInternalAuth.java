package net.lecousin.ant.service.provider.security;

import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import lombok.RequiredArgsConstructor;
import net.lecousin.ant.connector.database.DatabaseConnector;
import net.lecousin.ant.core.api.exceptions.BadRequestException;
import net.lecousin.ant.core.api.exceptions.UnauthorizedException;
import net.lecousin.ant.core.condition.Condition;
import net.lecousin.ant.core.springboot.connector.ConnectorService;
import net.lecousin.ant.core.springboot.security.JwtResponse;
import net.lecousin.ant.core.springboot.security.Permission;
import net.lecousin.ant.core.springboot.security.SecurityConstants;
import net.lecousin.ant.core.springboot.security.SecurityUtils;
import net.lecousin.ant.service.provider.security.db.RenewalEntity;
import net.lecousin.ant.service.provider.security.db.SubjectTypeEntity;
import net.lecousin.ant.service.security.SecurityServiceAuth;
import reactor.core.publisher.Mono;

@Service("securityServiceProviderInternalAuth")
@Primary
@RequiredArgsConstructor
public class SecurityServiceImplInternalAuth implements SecurityServiceAuth, InitializingBean {

	private final SecurityServiceImplSecrets secretsService;
	private final ConnectorService connectorService;
	private final SecurityServiceProperties properties;
	private final SecureRandom random;
	
	private Algorithm algo;
	private JWTVerifier verifier;
	
	@Override
	public void afterPropertiesSet() throws Exception {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(properties.getInternalAuthentication().getPrivateKeyBase64()));
		RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
		algo = Algorithm.RSA512(null, privateKey);
		verifier = JWT.require(algo).build();
	}
	
	@Override
	public Mono<JwtResponse> authenticateWithSecret(Optional<String> tenantId, String subjectType, String subjectId, String secret) {
		return secretsService.validateSecret(tenantId, subjectType, subjectId, secret)
			.switchIfEmpty(Mono.error(new UnauthorizedException()))
			.flatMap(permissions -> generateJwt(tenantId, subjectType, subjectId, permissions.stream().map(Permission::fromString).toList()));
	}
	
	@Override
	public Mono<JwtResponse> authenticated(Optional<String> tenantId, String subjectType, String subjectId, List<Permission> permissions) {
		return SecurityUtils.getAuthentication()
			.flatMap(auth -> {
				if (SecurityConstants.SUBJECT_TYPE_SERVICE.equals(subjectType))
					return Mono.error(new BadRequestException("subject type service is not allowed"));
				return connectorService.getConnector(DatabaseConnector.class)
				.flatMap(db -> db.findById(SubjectTypeEntity.class, subjectType))
				.filter(entity -> SecurityUtils.isSubject(auth, SecurityConstants.SUBJECT_TYPE_SERVICE, entity.getAuthorizedService()))
				.switchIfEmpty(Mono.error(new AccessDeniedException("subjectType " + subjectType)))
				.flatMap(r -> generateJwt(tenantId, subjectType, subjectId, permissions));
			});
	}
	
	@Override
	public Mono<JwtResponse> renewToken(String renewToken) {
		return SecurityUtils.getAuthentication()
			.flatMap(auth -> {
				DecodedJWT decoded = JWT.decode(renewToken);
		        verifier.verify(renewToken);
				String renewalId = decoded.getClaim("i").asString();
				String renewalSubject = decoded.getSubject();
				if (!renewalSubject.equals(auth.getPrincipal()))
					return Mono.error(new AccessDeniedException("Invalid token"));
				List<String> authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
				return connectorService.getConnector(DatabaseConnector.class)
				.flatMap(db ->
					db.find(RenewalEntity.class).where(Condition.field("id").is(renewalId)).executeSingle()
					.switchIfEmpty(Mono.error(new AccessDeniedException("Invalid token")))
					.flatMap(renewal -> {
						if (!renewal.getSubject().equals(renewalSubject))
							return Mono.error(new AccessDeniedException("Invalid token"));
						return db.delete(RenewalEntity.class, Condition.field("id").is(renewalId))
						.then(db.create(RenewalEntity.builder()
							.subject(renewalSubject)
							.expiresAt(Instant.now().plus(properties.getInternalAuthentication().getRenewTokenDuration()))
							.build()));
					})
					.map(renewal -> generate(renewalSubject, renewal, authorities))
				);
			});
	}
	
	@Override
	public Mono<Void> closeToken(String renewToken) {
		return SecurityUtils.getAuthentication()
		.flatMap(auth -> {
			DecodedJWT decoded = JWT.decode(renewToken);
	        verifier.verify(renewToken);
			String renewalId = decoded.getClaim("i").asString();
			String renewalSubject = decoded.getSubject();
			if (!renewalSubject.equals(auth.getPrincipal()))
				return Mono.error(new AccessDeniedException("Invalid token"));
			return connectorService.getConnector(DatabaseConnector.class)
			.flatMap(db -> db.delete(RenewalEntity.class, Condition.field("id").is(renewalId)));
		});
	}
	
	private Mono<JwtResponse> generateJwt(Optional<String> tenantId, String subjectType, String subjectId, List<Permission> permissions) {
		String subject = subjectType + ':' + subjectId;
		List<String> authorities = new LinkedList<>();
		permissions.forEach(p -> authorities.add(p.toAuthority()));
		if (tenantId.isPresent()) authorities.add(SecurityConstants.AUTHORITY_TENANT_PREFIX + tenantId.get());
		return connectorService.getConnector(DatabaseConnector.class)
			.flatMap(db -> db.create(RenewalEntity.builder().subject(subject).expiresAt(Instant.now().plus(properties.getInternalAuthentication().getRenewTokenDuration())).build()))
			.map(renewal -> generate(subject, renewal, authorities));
	}
	
	private JwtResponse generate(String subject, RenewalEntity renewal, List<String> authorities) {
		Instant accessTokenExpiresAt = Instant.now().plus(properties.getInternalAuthentication().getTokenDuration());
		String accessToken = JWT.create()
			.withSubject(subject)
			.withExpiresAt(accessTokenExpiresAt)
			.withClaim("r", random.nextLong())
			.withClaim(SecurityConstants.CLAIM_AUTHORITIES, authorities)
			.sign(algo);
		String renewToken = JWT.create()
			.withExpiresAt(renewal.getExpiresAt())
			.withClaim("r", random.nextLong())
			.withClaim("i", renewal.getId())
			.sign(algo);
		return new JwtResponse(accessToken, accessTokenExpiresAt, renewToken, renewal.getExpiresAt());
	}
}
