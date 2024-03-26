package net.lecousin.ant.service.provider.security.exceptions;

import net.lecousin.ant.core.api.exceptions.ForbiddenException;
import net.lecousin.commons.io.text.i18n.TranslatedString;

public class SubjectTypeNotAllowedException extends ForbiddenException {

	private static final long serialVersionUID = 1L;

	public SubjectTypeNotAllowedException(String subjectType) {
		super(new TranslatedString("service-security", "subject type {} not allowed", subjectType));
	}
	
}
