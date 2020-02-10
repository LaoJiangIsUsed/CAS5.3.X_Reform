//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.web.flow.login;

import java.util.List;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.Generated;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.RegisteredServiceAccessStrategy;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.web.support.ArgumentExtractor;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.apereo.cas.web.support.CookieValueManager;
import org.apereo.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.repository.NoSuchFlowExecutionException;

public class InitialFlowSetupAction extends AbstractAction {
    @Generated
    private static final Logger LOGGER = LoggerFactory.getLogger(InitialFlowSetupAction.class);
    private final List<ArgumentExtractor> argumentExtractors;
    private final ServicesManager servicesManager;
    private final AuthenticationServiceSelectionPlan authenticationRequestServiceSelectionStrategies;
    private final CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator;
    private final CookieRetrievingCookieGenerator warnCookieGenerator;
    private final CasConfigurationProperties casProperties;

    @Autowired
    private CookieValueManager cookieValueManager;
    @Override
    public Event doExecute(final RequestContext context) {
        HttpServletRequest request = WebUtils.getHttpServletRequestFromExternalWebflowContext(context);
        if (request.getMethod().equalsIgnoreCase(HttpMethod.POST.name())) {
            WebUtils.putInitialHttpRequestPostParameters(context);
        }

        this.configureCookieGenerators(context);
        this.configureWebflowContext(context);
        this.configureWebflowContextForService(context);
        return this.success();
    }

    private void configureWebflowContextForService(final RequestContext context) {
        Service service = WebUtils.getService(this.argumentExtractors, context);
        if (service != null) {
            LOGGER.debug("Placing service in context scope: [{}]", service.getId());
            Service selectedService = this.authenticationRequestServiceSelectionStrategies.resolveService(service);
            RegisteredService registeredService = this.servicesManager.findServiceBy(selectedService);
            if (registeredService != null && registeredService.getAccessStrategy().isServiceAccessAllowed()) {
                LOGGER.debug("Placing registered service [{}] with id [{}] in context scope", registeredService.getServiceId(), registeredService.getId());
                WebUtils.putRegisteredService(context, registeredService);
                RegisteredServiceAccessStrategy accessStrategy = registeredService.getAccessStrategy();
                if (accessStrategy.getUnauthorizedRedirectUrl() != null) {
                    LOGGER.debug("Placing registered service's unauthorized redirect url [{}] with id [{}] in context scope", accessStrategy.getUnauthorizedRedirectUrl(), registeredService.getServiceId());
                    WebUtils.putUnauthorizedRedirectUrl(context, accessStrategy.getUnauthorizedRedirectUrl());
                }
            }
        } else if (!this.casProperties.getSso().isAllowMissingServiceParameter()) {
            LOGGER.warn("No service authentication request is available at [{}]. CAS is configured to disable the flow.", WebUtils.getHttpServletRequestFromExternalWebflowContext(context).getRequestURL());
            throw new NoSuchFlowExecutionException(context.getFlowExecutionContext().getKey(), new UnauthorizedServiceException("screen.service.required.message", "Service is required"));
        }

        WebUtils.putService(context, service);
    }

    private void configureWebflowContext(final RequestContext context) {
        HttpServletRequest request = WebUtils.getHttpServletRequestFromExternalWebflowContext(context);

        String cookie=this.ticketGrantingTicketCookieGenerator.retrieveCookieValue(request);
        if (cookie==null && "/cas/login".equals(request.getRequestURI())) {
            String tgc=request.getParameter("tgc");
            if (tgc!=null && !"".equals(tgc.trim())) {
               // cookie = cookieValueManager.buildCookieValue(tgc,request);
                cookie=tgc;

                HttpServletResponse response = WebUtils.getHttpServletResponseFromExternalWebflowContext(context);
//                Cookie tgcCookie=new Cookie(this.ticketGrantingTicketCookieGenerator.getCookieName(),cookie);
                Cookie tgcCookie=new Cookie(this.ticketGrantingTicketCookieGenerator.getCookieName(), cookieValueManager.buildCookieValue(tgc,request));
                if (this.ticketGrantingTicketCookieGenerator.getCookieDomain() != null) {
                    tgcCookie.setDomain(this.ticketGrantingTicketCookieGenerator.getCookieDomain());
                }
                if (this.ticketGrantingTicketCookieGenerator.getCookiePath() != null) {
                    tgcCookie.setPath(this.ticketGrantingTicketCookieGenerator.getCookiePath());
                }
                if (this.ticketGrantingTicketCookieGenerator.getCookieMaxAge() != null) {
                    tgcCookie.setMaxAge(this.ticketGrantingTicketCookieGenerator.getCookieMaxAge());
                }
                if (this.ticketGrantingTicketCookieGenerator.isCookieSecure()) {
                    tgcCookie.setSecure(true);
                }
                if (this.ticketGrantingTicketCookieGenerator.isCookieHttpOnly()) {
                    tgcCookie.setHttpOnly(true);
                }
                response.addCookie(tgcCookie);
            }
        }
        WebUtils.putTicketGrantingTicketInScopes(context, cookie);

        WebUtils.putWarningCookie(context, Boolean.valueOf(this.warnCookieGenerator.retrieveCookieValue(request)));
        WebUtils.putGoogleAnalyticsTrackingIdIntoFlowScope(context, this.casProperties.getGoogleAnalytics().getGoogleAnalyticsTrackingId());
        WebUtils.putGeoLocationTrackingIntoFlowScope(context, this.casProperties.getEvents().isTrackGeolocation());
        WebUtils.putPasswordManagementEnabled(context, this.casProperties.getAuthn().getPm().isEnabled());
        WebUtils.putRememberMeAuthenticationEnabled(context, this.casProperties.getTicket().getTgt().getRememberMe().isEnabled());
        WebUtils.putStaticAuthenticationIntoFlowScope(context, StringUtils.isNotBlank(this.casProperties.getAuthn().getAccept().getUsers()) || StringUtils.isNotBlank(this.casProperties.getAuthn().getReject().getUsers()));
    }

    private void configureCookieGenerators(final RequestContext context) {
        String contextPath = context.getExternalContext().getContextPath();
        String cookiePath = StringUtils.isNotBlank(contextPath) ? contextPath + '/' : "/";
        if (StringUtils.isBlank(this.warnCookieGenerator.getCookiePath())) {
            LOGGER.info("Setting path for cookies for warn cookie generator to: [{}] ", cookiePath);
            this.warnCookieGenerator.setCookiePath(cookiePath);
        } else {
            LOGGER.debug("Warning cookie path is set to [{}] and path [{}]", this.warnCookieGenerator.getCookieDomain(), this.warnCookieGenerator.getCookiePath());
        }

        if (StringUtils.isBlank(this.ticketGrantingTicketCookieGenerator.getCookiePath())) {
            LOGGER.debug("Setting path for cookies for TGC cookie generator to: [{}] ", cookiePath);
            this.ticketGrantingTicketCookieGenerator.setCookiePath(cookiePath);
        } else {
            LOGGER.debug("TGC cookie path is set to [{}] and path [{}]", this.ticketGrantingTicketCookieGenerator.getCookieDomain(), this.ticketGrantingTicketCookieGenerator.getCookiePath());
        }

    }

    public ServicesManager getServicesManager() {
        return this.servicesManager;
    }

    @Generated
    public InitialFlowSetupAction(final List<ArgumentExtractor> argumentExtractors, final ServicesManager servicesManager, final AuthenticationServiceSelectionPlan authenticationRequestServiceSelectionStrategies, final CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator, final CookieRetrievingCookieGenerator warnCookieGenerator, final CasConfigurationProperties casProperties) {
        this.argumentExtractors = argumentExtractors;
        this.servicesManager = servicesManager;
        this.authenticationRequestServiceSelectionStrategies = authenticationRequestServiceSelectionStrategies;
        this.ticketGrantingTicketCookieGenerator = ticketGrantingTicketCookieGenerator;
        this.warnCookieGenerator = warnCookieGenerator;
        this.casProperties = casProperties;
    }
}
