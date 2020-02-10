package com.sso.cas.custom.action;

import com.sso.cas.custom.entity.CustomCredential;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;


/**
 *
 * @author Administrator
 */
public class ValidateLoginAction extends AbstractAction {

    private static final String USERTYPE_CODE = "usertypeError";


    /**
     * 是否开启验证码
     *
     * @return
     */
    private boolean isEnable() {
        return false;
    }


    @Override
    protected Event doExecute(RequestContext context) throws Exception {
        CustomCredential credential = (CustomCredential) WebUtils.getCredential(context);

        System.out.println("excute");

        //系统信息不为空才检测校验码
        if (credential instanceof CustomCredential) {

            String usertype = credential.getUsertype();
            if ("".equals(usertype) || usertype == null) {
                return getError(context, USERTYPE_CODE);
            }

        }
        return null;
    }

    /**
     * 跳转到错误页
     *
     * @param requestContext
     * @return
     */
    private Event getError(final RequestContext requestContext, String CODE) {
        final MessageContext messageContext = requestContext.getMessageContext();
        messageContext.addMessage(new MessageBuilder().error().code(CODE).build());
        return getEventFactorySupport().event(this, CODE);
    }


}
