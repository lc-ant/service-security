package net.lecousin.ant.service.provider.security.db;

import java.time.Instant;

import org.springframework.data.annotation.Id;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.lecousin.ant.connector.database.annotations.Entity;
import net.lecousin.ant.connector.database.annotations.GeneratedValue;

@Entity(domain = "security", name = "renewal")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RenewalEntity {

	@Id
	@GeneratedValue
	private String id;
	
	private String subject;
	private Instant expiresAt;
	
}
