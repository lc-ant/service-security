package net.lecousin.ant.service.provider.security.db;

import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import org.springframework.data.annotation.Id;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.lecousin.ant.connector.database.annotations.Entity;
import net.lecousin.ant.connector.database.annotations.GeneratedValue;
import net.lecousin.ant.connector.database.annotations.Tenant;

@Entity(domain = "security", name = "secret")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecretEntity {

	@Id
	@GeneratedValue
	private String id;
	
	@Tenant
	private Optional<String> tenantId;
	
	private String subjectType;
	private String subjectId;
	private String secret;
	
	@Builder.Default
	private List<String> permissions = new LinkedList<>();
	
}
