package net.lecousin.ant.service.security.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import net.lecousin.ant.core.validation.annotations.Mandatory;

@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class AuthenticationWithAuthoritiesRequest extends AuthenticationRequest {

	@Mandatory
	private List<String> authorities;
	
	private boolean root;
	
}
