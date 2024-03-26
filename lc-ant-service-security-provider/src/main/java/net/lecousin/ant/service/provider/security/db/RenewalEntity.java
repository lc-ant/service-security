package net.lecousin.ant.service.provider.security.db;

import java.time.Instant;

import org.springframework.data.annotation.Id;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.lecousin.ant.connector.database.annotations.Entity;
import net.lecousin.ant.connector.database.annotations.GeneratedValue;
import net.lecousin.ant.core.api.ApiData;
import net.lecousin.ant.core.expression.impl.StringFieldReference;
import net.lecousin.ant.core.expression.impl.TemporalFieldReference;

@Entity(domain = "security", name = "renewal")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RenewalEntity {
	
	public static StringFieldReference FIELD_ID = ApiData.FIELD_ID;
	public static TemporalFieldReference<Instant> FIELD_ISSUED_AT = new TemporalFieldReference<>("issuedAt");
	public static TemporalFieldReference<Instant> FIELD_EXPIRES_AT = new TemporalFieldReference<>("expiresAt");
	public static StringFieldReference FIELD_ACCESS_TOKEN = new StringFieldReference("accessToken");

	@Id
	@GeneratedValue
	private String id;
	
	private String subject;
	private Instant issuedAt;
	private Instant expiresAt;
	private String accessToken;
	
}
