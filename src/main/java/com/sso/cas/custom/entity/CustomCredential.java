
package com.sso.cas.custom.entity;

import org.apereo.cas.authentication.UsernamePasswordCredential;
import javax.validation.constraints.Size;

/**
 * 自定义Credential 新增参数
 * @author Administrator
 */
public class CustomCredential extends UsernamePasswordCredential {

    @Size(min = 1, message = "required.usertype")
    private String usertype;

    public CustomCredential(String username, String password, String usertype) {
        super(username, password);
        this.usertype = usertype;
    }

    public CustomCredential(String username, String password) {
        super(username, password);
    }

    public CustomCredential() {
    }

    public CustomCredential(String usertype) {
        this.usertype = usertype;
    }

    public String getUsertype() {
        return usertype;
    }

    public void setUsertype(String usertype) {
        this.usertype = usertype;
    }
}
