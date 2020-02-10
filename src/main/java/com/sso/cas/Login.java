package com.sso.cas;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 登录验证器
 * @author Administrator
 */
public class Login extends AbstractUsernamePasswordAuthenticationHandler {
    public Login(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword) throws GeneralSecurityException, PreventedException {
        DriverManagerDataSource driverManagerDataSource = new DriverManagerDataSource();
        driverManagerDataSource.setDriverClassName("com.mysql.jdbc.Driver");
        driverManagerDataSource.setUrl("jdbc:mysql://127.0.0.1:3306/sso?useUnicode=true&characterEncoding=UTF-8&serverTimezone=UTC");
        driverManagerDataSource.setUsername("root");
        driverManagerDataSource.setPassword("123456");
        JdbcTemplate template = new JdbcTemplate();
        template.setDataSource(driverManagerDataSource);

        String username = credential.getUsername();
        String password = credential.getPassword();
        //这里后续处理密码加解密

        Map<String,Object> userMap = template.queryForMap("SELECT `password` FROM sso_user WHERE username = ?",username);
        if(null == userMap){
            throw new FailedLoginException("没有该用户");
        }
         //返回多属性
        Map<String, Object> map=new HashMap<>();
        map.put("email", "XXXXX@qq.com");
        //BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
//        if(encoder.matches(password,String.valueOf(userMap.get("password")))){
//            return createHandlerResult(credential, principalFactory.createPrincipal(username, map), null);
//        }
        //数据库密码加密还需处理
        if(String.valueOf(userMap.get("password")).equals(password)){
            return createHandlerResult(credential, principalFactory.createPrincipal(username, map), Collections.emptyList());
        }
        throw new FailedLoginException("Sorry, login attemp failed.");
    }

}
