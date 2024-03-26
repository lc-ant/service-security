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
import net.lecousin.ant.connector.database.annotations.Index;
import net.lecousin.ant.connector.database.annotations.Tenant;
import net.lecousin.ant.connector.database.model.IndexType;
import net.lecousin.ant.core.api.ApiData;
import net.lecousin.ant.core.expression.impl.StringFieldReference;

@Entity(domain = "security", name = "secret")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Index(fields = {"tenantId", "subjectType", "subjectId"}, type = IndexType.UNIQUE)
public class SecretEntity {
	
	public static final StringFieldReference FIELD_ID = ApiData.FIELD_ID;
	public static final StringFieldReference.Nullable FIELD_TENANT_ID = new StringFieldReference.Nullable("tenantId");
	public static final StringFieldReference FIELD_SUBJECT_TYPE = new StringFieldReference("subjectType");
	public static final StringFieldReference FIELD_SUBJECT_ID = new StringFieldReference("subjectId");
	public static final StringFieldReference FIELD_SECRET = new StringFieldReference("secret");

	@Id
	@GeneratedValue
	private String id;
	
	@Tenant
	private Optional<String> tenantId;
	
	private String subjectType;
	private String subjectId;
	private String secret;
	
	@Builder.Default
	private List<String> authorities = new LinkedList<>();
	
}
