package com.sso.cas.custom.exection;

import org.apereo.cas.authentication.AuthenticationException;

/**
 * @author Administrator
 */
public class CheckCodeErrorException extends AuthenticationException {
    public CheckCodeErrorException(){
        super();
    }


    public CheckCodeErrorException(String msg) {
        super(msg);
    }
}
