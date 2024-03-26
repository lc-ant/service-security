package net.lecousin.ant.service.provider.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ConfigurationProperties(prefix = "lc-ant.service.security")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityServiceProperties {

	private String privateKey;
	
}
