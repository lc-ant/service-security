package net.lecousin.ant.service.provider.security.db;

import org.springframework.data.annotation.Id;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.lecousin.ant.connector.database.annotations.Entity;

@Entity(domain = "security", name = "subject_types")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SubjectTypeEntity {

	@Id
	private String subjectType;
	
	private String authorizedService;
	
}
