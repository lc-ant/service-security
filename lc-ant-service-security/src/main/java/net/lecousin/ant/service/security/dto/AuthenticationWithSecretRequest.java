package net.lecousin.ant.service.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import net.lecousin.ant.core.validation.annotations.Mandatory;
import net.lecousin.ant.core.validation.annotations.StringConstraint;

@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class AuthenticationWithSecretRequest extends AuthenticationRequest {

	@Mandatory
	@StringConstraint(minLength = 8)
	private String secret;
	
}
