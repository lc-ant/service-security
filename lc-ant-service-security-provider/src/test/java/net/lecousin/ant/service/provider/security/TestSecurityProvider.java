package net.lecousin.ant.service.provider.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.TestTemplate;
import org.springframework.context.annotation.Import;

import net.lecousin.ant.core.security.Root;
import net.lecousin.ant.core.springboot.service.client.LcAntServiceClientConfiguration;
import net.lecousin.ant.core.springboot.test.LcAntServiceTest;
import net.lecousin.ant.core.springboot.test.TestWithBeans;
import net.lecousin.ant.core.springboot.test.WithMockInternalAuthentication;
import net.lecousin.ant.service.security.SecurityService;
import net.lecousin.ant.service.security.dto.AuthenticationWithSecretRequest;

@LcAntServiceTest(service = "security")
@Import({SecurityServiceConfiguration.class, LcAntServiceClientConfiguration.class})
@TestWithBeans(value = SecurityService.class, qualifiers = { "securityServiceProvider", "securityServiceRestControllerV1", "securityServiceRestClientV1" })
class TestSecurityProvider {

	@TestTemplate
	@WithMockInternalAuthentication(authorities = Root.AUTHORITY)
	void test(SecurityService service) {
		service.secrets().setSecret(Optional.empty(), "service", "test", "test123456").block();
		var jwt = service.internalAuth().authenticateWithSecret(
			AuthenticationWithSecretRequest.builder()
			.tenantId(Optional.empty())
			.subjectType("service")
			.subjectId("test")
			.secret("test123456")
			.tokenDuration(Duration.ofMinutes(15))
			.renewTokenDuration(Duration.ofMinutes(30))
			.build()
		).block();
		assertThat(jwt.getAccessToken()).isNotNull();
	}
}
