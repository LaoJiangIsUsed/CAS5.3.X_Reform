//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.web.flow.resolver.impl;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.Generated;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.AuthenticationContextValidator;
import org.apereo.cas.authentication.AuthenticationResultBuilder;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.services.MultifactorAuthenticationProvider;
import org.apereo.cas.services.MultifactorAuthenticationProviderSelector;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.support.WebUtils;
import org.apereo.inspektr.audit.annotation.Audit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RankedAuthenticationProviderWebflowEventResolver extends AbstractCasWebflowEventResolver {
    @Generated
    private static final Logger LOGGER = LoggerFactory.getLogger(RankedAuthenticationProviderWebflowEventResolver.class);
    private final CasDelegatingWebflowEventResolver initialAuthenticationAttemptWebflowEventResolver;
    private final AuthenticationContextValidator authenticationContextValidator;

    public RankedAuthenticationProviderWebflowEventResolver(final AuthenticationSystemSupport authenticationSystemSupport, final CentralAuthenticationService centralAuthenticationService, final ServicesManager servicesManager, final TicketRegistrySupport ticketRegistrySupport, final CookieGenerator warnCookieGenerator, final AuthenticationServiceSelectionPlan authenticationSelectionStrategies, final MultifactorAuthenticationProviderSelector selector, final AuthenticationContextValidator authenticationContextValidator, final CasDelegatingWebflowEventResolver casDelegatingWebflowEventResolver) {
        super(authenticationSystemSupport, centralAuthenticationService, servicesManager, ticketRegistrySupport, warnCookieGenerator, authenticationSelectionStrategies, selector);
        this.authenticationContextValidator = authenticationContextValidator;
        this.initialAuthenticationAttemptWebflowEventResolver = casDelegatingWebflowEventResolver;
    }

    @Override
    public Set<Event> resolveInternal(final RequestContext context) {
        String tgt = WebUtils.getTicketGrantingTicketId(context);
        RegisteredService service = WebUtils.getRegisteredService(context);
        if (service == null) {
            LOGGER.debug("No service is available to determine event for principal");
            return this.resumeFlow();
        } else if (StringUtils.isBlank(tgt)) {
            redirectToLoginUrl(context);
            LOGGER.trace("TGT is blank; proceed with flow normally.");
            return this.resumeFlow();
        } else {
            Authentication authentication = this.ticketRegistrySupport.getAuthenticationFrom(tgt);
            if (authentication == null) {
                redirectToLoginUrl(context);
                LOGGER.trace("TGT has no authentication and is blank; proceed with flow normally.");
                return this.resumeFlow();
            } else {
                Credential credential = WebUtils.getCredential(context);
                AuthenticationResultBuilder builder = this.authenticationSystemSupport.establishAuthenticationContextFromInitial(authentication, credential);
                LOGGER.debug("Recording and tracking initial authentication results in the request context");
                WebUtils.putAuthenticationResultBuilder(builder, context);
                WebUtils.putAuthentication(authentication, context);
                Event event = this.initialAuthenticationAttemptWebflowEventResolver.resolveSingle(context);
                if (event == null) {
                    LOGGER.trace("Request does not indicate a requirement for authentication policy; proceed with flow normally.");
                    return this.resumeFlow();
                } else {
                    String id = event.getId();
                    LOGGER.debug("Resolved event from the initial authentication leg is [{}]", id);
                    if (!id.equals("error") && !id.equals("authenticationFailure") && !id.equals("success") && !id.equals("successWithWarnings")) {
                        LOGGER.debug("Validating authentication context for event [{}] and service [{}]", id, service);
                        Pair<Boolean, Optional<MultifactorAuthenticationProvider>> result = this.authenticationContextValidator.validate(authentication, id, service);
                        if ((Boolean)result.getKey()) {
                            LOGGER.debug("Authentication context is successfully validated by [{}] for service [{}]", id, service);
                            return this.resumeFlow();
                        } else {
                            Optional<MultifactorAuthenticationProvider> value = (Optional)result.getValue();
                            if (value.isPresent()) {
                                Map<String, Object> attributeMap = buildEventAttributeMap(authentication.getPrincipal(), service, (MultifactorAuthenticationProvider)value.get());
                                return CollectionUtils.wrapSet(this.validateEventIdForMatchingTransitionInContext(id, context, attributeMap));
                            } else {
                                LOGGER.warn("The authentication context cannot be satisfied and the requested event [{}] is unrecognized", id);
                                return CollectionUtils.wrapSet(new Event(this, "error"));
                            }
                        }
                    } else {
                        LOGGER.debug("Returning webflow event as [{}]", id);
                        return CollectionUtils.wrapSet(event);
                    }
                }
            }
        }
    }

    @Override
    @Audit(
            action = "AUTHENTICATION_EVENT",
            actionResolverName = "AUTHENTICATION_EVENT_ACTION_RESOLVER",
            resourceResolverName = "AUTHENTICATION_EVENT_RESOURCE_RESOLVER"
    )
    public Event resolveSingle(final RequestContext context) {
        return super.resolveSingle(context);
    }

    private Set<Event> resumeFlow() {
        return CollectionUtils.wrapSet((new EventFactorySupport()).success(this));
    }

    /**
     *
     * 重定向到request参数中指明的登陆页面
     * @param context
     */
    private void redirectToLoginUrl(final RequestContext context) {
        HttpServletRequest request=WebUtils.getHttpServletRequestFromExternalWebflowContext();
        String loginUrl=request.getParameter("loginUrl");

        if (loginUrl!=null) {
            HttpServletResponse response = WebUtils.getHttpServletResponseFromExternalWebflowContext(context);
            try {
                response.sendRedirect(loginUrl+"?checked=1");
            } catch (IOException e) {
//                throw new DhccCasException(e.getMessage(),e);
            }
        }
    }

}
