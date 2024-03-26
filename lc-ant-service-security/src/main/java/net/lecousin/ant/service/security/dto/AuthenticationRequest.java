package net.lecousin.ant.service.security.dto;

import java.time.Duration;
import java.util.Optional;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import net.lecousin.ant.core.validation.annotations.Mandatory;
import net.lecousin.ant.core.validation.annotations.StringConstraint;

@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class AuthenticationRequest {

	private Optional<String> tenantId;
	@Mandatory
	@StringConstraint(minLength = 3)
	private String subjectType;
	@Mandatory
	@StringConstraint(minLength = 3)
	private String subjectId;
	@Mandatory
	private Duration tokenDuration;
	@Mandatory
	private Duration renewTokenDuration;
	
}
