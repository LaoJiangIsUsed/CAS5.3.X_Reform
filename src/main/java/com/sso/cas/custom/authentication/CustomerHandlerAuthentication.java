package com.sso.cas.custom.authentication;

import com.sso.cas.custom.entity.CustomCredential;

import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 自定义参数 新增 usertype
 * @author Administrator
 */
public class CustomerHandlerAuthentication extends AbstractPreAndPostProcessingAuthenticationHandler {

    public CustomerHandlerAuthentication(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    public boolean supports(Credential credential) {
//        return credential instanceof UsernamePasswordCredential;
        //判断传递过来的Credential 是否是自己能处理的类型
        return credential instanceof CustomCredential;
    }

    @Override
    protected AuthenticationHandlerExecutionResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {

        CustomCredential customCredential = (CustomCredential) credential;

        String username = customCredential.getUsername();
        String password = customCredential.getPassword();
        String usertype = customCredential.getUsertype();


        // 添加其他判断逻辑

        System.out.println("username : " + username);
        System.out.println("password : " + password);
        System.out.println("usertype : " + usertype);



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
        if(userMap == null){
            throw new FailedLoginException("没有该用户!");
        }


        if (!String.valueOf(userMap.get("password")).equals(password)) {
            throw new FailedLoginException("密码错误!");
        } else {

            final List<MessageDescriptor> list = new ArrayList<>();
            // 可自定义返回给客户端的多个属性信息
            HashMap<String, Object> returnInfo = new HashMap<>(3);
            returnInfo.put("email", "123@qq.com");
            returnInfo.put("other", "other");
            returnInfo.put("password", userMap.get("password"));

            return createHandlerResult(customCredential,
                    this.principalFactory.createPrincipal(username, returnInfo), list);
        }


    }
}
