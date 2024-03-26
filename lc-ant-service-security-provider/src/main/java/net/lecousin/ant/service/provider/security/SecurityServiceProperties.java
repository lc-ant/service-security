package net.lecousin.ant.service.provider.security;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ConfigurationProperties(prefix = "security-service-provider")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityServiceProperties {

	private InternalAuthentication internalAuthentication = new InternalAuthentication();
	
	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class InternalAuthentication {
		private String privateKeyBase64;
		private Duration tokenDuration = Duration.ofMinutes(30);
		private Duration renewTokenDuration = Duration.ofMinutes(35);
	}
	
}
