//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.rest.factory;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

import com.sso.cas.custom.entity.CustomCredential;
import lombok.Generated;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.MultiValueMap;

public class UsernamePasswordRestHttpRequestCredentialFactory implements RestHttpRequestCredentialFactory {
    @Generated
    private static final Logger LOGGER = LoggerFactory.getLogger(UsernamePasswordRestHttpRequestCredentialFactory.class);
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private int order;

    public UsernamePasswordRestHttpRequestCredentialFactory() {
    }

    @Override
    public List<Credential> fromRequest(final HttpServletRequest request, final MultiValueMap<String, String> requestBody) {
        if (requestBody != null && !requestBody.isEmpty()) {
            String username = (String)requestBody.getFirst("username");
            String password = (String)requestBody.getFirst("password");
            String usertype = (String)requestBody.getFirst("usertype");
            if (username != null && password != null) {
                Credential c;
                if(usertype != null){
                    c = new CustomCredential(username, password,usertype);
                }else{
                    c = new CustomCredential(username, password);
                }

                return CollectionUtils.wrap(c);
            } else {
                LOGGER.debug("Invalid payload. 'username' and 'password' form fields are required.");
                return new ArrayList(0);
            }
        } else {
            LOGGER.debug("Skipping {} because the requestBody is null or empty", this.getClass().getSimpleName());
            return new ArrayList(0);
        }
    }

    @Override
    @Generated
    public int getOrder() {
        return this.order;
    }
}
