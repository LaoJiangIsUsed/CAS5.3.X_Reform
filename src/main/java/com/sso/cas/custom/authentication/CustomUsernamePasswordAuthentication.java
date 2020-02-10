package com.sso.cas.custom.authentication;



import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * 接收默认参数 只有username password
 * @author Administrator
 */
public class CustomUsernamePasswordAuthentication extends AbstractUsernamePasswordAuthenticationHandler {

    public CustomUsernamePasswordAuthentication(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential usernamePasswordCredential, String s) throws GeneralSecurityException, PreventedException {

        String username = usernamePasswordCredential.getUsername();
        String password = usernamePasswordCredential.getPassword();
        // 添加其他判断逻辑
        System.out.println("username : " + username);
        System.out.println("password : " + password);

        // JDBC模板依赖于连接池来获得数据的连接，所以必须先要构造连接池
        DriverManagerDataSource driverManagerDataSource = new DriverManagerDataSource();
        driverManagerDataSource.setDriverClassName("com.mysql.jdbc.Driver");
        driverManagerDataSource.setUrl("jdbc:mysql://127.0.0.1:3306/sso?useUnicode=true&characterEncoding=UTF-8&serverTimezone=UTC");
        driverManagerDataSource.setUsername("root");
        driverManagerDataSource.setPassword("");
        // 创建JDBC模板
        JdbcTemplate template = new JdbcTemplate();
        template.setDataSource(driverManagerDataSource);

        Map<String,Object> userMap = template.queryForMap("SELECT `password` FROM sso_user WHERE username = ?",username);
        if(null == userMap){
            throw new FailedLoginException("没有该用户!");
        }


        if (!String.valueOf(userMap.get("password")).equals(password)) {
            throw new FailedLoginException("密码错误!");
        } else {

            final List<MessageDescriptor> list = new ArrayList<>();
            // 可自定义返回给客户端的多个属性信息
            HashMap<String, Object> returnInfo = new HashMap<>();
            returnInfo.put("email", "123@qq.com");
            returnInfo.put("username", userMap.get("username"));
            returnInfo.put("password", userMap.get("password"));

            return createHandlerResult(usernamePasswordCredential,
                    this.principalFactory.createPrincipal(username, returnInfo), list);
        }


    }
}
