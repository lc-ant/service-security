package net.lecousin.ant.service.provider.security;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import net.lecousin.ant.core.springboot.service.provider.LcAntServiceProviderConfiguration;

@Configuration
@Import(LcAntServiceProviderConfiguration.class)
@EnableConfigurationProperties(SecurityServiceProperties.class)
public class SecurityServiceConfiguration {

}
