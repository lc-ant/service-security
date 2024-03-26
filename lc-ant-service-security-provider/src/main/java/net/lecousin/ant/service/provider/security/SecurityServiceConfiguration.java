package net.lecousin.ant.service.provider.security;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import net.lecousin.ant.connector.database.DatabaseConnectorConfiguration;
import net.lecousin.ant.core.springboot.service.provider.LcAntServiceProviderConfiguration;
import net.lecousin.ant.service.jobcontrol.JobControlConfiguration;

@Configuration
@EnableAutoConfiguration
@Import({LcAntServiceProviderConfiguration.class, DatabaseConnectorConfiguration.class, JobControlConfiguration.class})
@EnableConfigurationProperties(SecurityServiceProperties.class)
@ComponentScan
public class SecurityServiceConfiguration {

}
