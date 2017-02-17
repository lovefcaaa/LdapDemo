package org.main.test;

import java.io.File;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.FileSystemXmlApplicationContext;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

public class MySpringLdapDemo {

	protected static final Log log = LogFactory.getLog(MySpringLdapDemo.class);

	public static void main(String[] args) {

		String basepath = new File("").getAbsolutePath();
		String path1 = basepath
				+ "/src/main/resources/applicationContext-ldap.xml";
		ApplicationContext ac = new FileSystemXmlApplicationContext(path1);

		testInLdapTemplate(ac);
//		testKylinAuth(ac);
//		testSearchSingleAttribute(ac);

	}
	
	public static void testSearchSingleAttribute(ApplicationContext ac){
		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate((ContextSource) ac.getBean("ldapSource"));

	    Set<String> userRoles = template.searchForSingleAttributeValues("ou=Group,dc=openldap,dc=jw,dc=cn", "(member={0})",
	            new String[]{"uid=hadoop,ou=People,dc=openldap,dc=jw,dc=cn", "hadoop"}, "cn");
	    log.debug("Using filter: " + userRoles);
	}

	

	public static void testKylinAuth(ApplicationContext ac) {
		KylinAuthenticationProvider provider = (KylinAuthenticationProvider) ac
				.getBean("kylinUserAuthProvider");
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("hadoop", "apU)u%7lk,-7o");
		log.info("provider: " + provider.getClass().getName());
		Authentication au = provider.authenticate(authentication);
		log.info(au);
		log.info(au.getCredentials());
		log.info(au.getPrincipal());
		log.info(au.getDetails());
	}

	/**
	 * 使用LdapTemplate认证
	 * @param ac
	 */
	public static void testInLdapTemplate(ApplicationContext ac) {
		LdapTemplate lt = (LdapTemplate) ac.getBean("ldapTemplate");

		AndFilter filter = new AndFilter();
		filter.and(new EqualsFilter("uid", "hadoop"));
		boolean b = lt.authenticate("", filter.toString(), "apU)u%7lk,-7o");
		log.info("登录陈宫?"+b);
	}
}