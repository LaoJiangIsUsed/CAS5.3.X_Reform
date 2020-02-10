package org.apereo.cas.web.flow.config;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import lombok.Generated;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.PrincipalElectionStrategy;
import org.apereo.cas.authentication.adaptive.AdaptiveAuthenticationPolicy;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.logout.LogoutManager;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.FlowExecutionExceptionResolver;
import org.apereo.cas.web.flow.GatewayServicesManagementCheck;
import org.apereo.cas.web.flow.GenerateServiceTicketAction;
import org.apereo.cas.web.flow.ServiceAuthorizationCheck;
import org.apereo.cas.web.flow.SingleSignOnParticipationStrategy;
import org.apereo.cas.web.flow.actions.InitialAuthenticationAction;
import org.apereo.cas.web.flow.login.*;
import org.apereo.cas.web.flow.logout.FrontChannelLogoutAction;
import org.apereo.cas.web.flow.logout.LogoutAction;
import org.apereo.cas.web.flow.logout.LogoutViewSetupAction;
import org.apereo.cas.web.flow.logout.TerminateSessionAction;
import org.apereo.cas.web.flow.mfa.MultifactorAuthenticationAvailableAction;
import org.apereo.cas.web.flow.mfa.MultifactorAuthenticationBypassAction;
import org.apereo.cas.web.flow.mfa.MultifactorAuthenticationFailureAction;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.CasWebflowEventResolver;
import org.apereo.cas.web.support.ArgumentExtractor;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.execution.Action;

@Configuration("casSupportActionsConfiguration")
@EnableConfigurationProperties({CasConfigurationProperties.class})
@EnableTransactionManagement(
        proxyTargetClass = true
)
public class CasSupportActionsConfiguration {
    @Generated
    private static final Logger LOGGER = LoggerFactory.getLogger(CasSupportActionsConfiguration.class);
    @Autowired
    @Qualifier("serviceTicketRequestWebflowEventResolver")
    private CasWebflowEventResolver serviceTicketRequestWebflowEventResolver;
    @Autowired
    @Qualifier("initialAuthenticationAttemptWebflowEventResolver")
    private CasDelegatingWebflowEventResolver initialAuthenticationAttemptWebflowEventResolver;
    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;
    @Autowired
    @Qualifier("ticketGrantingTicketCookieGenerator")
    private ObjectProvider<CookieRetrievingCookieGenerator> ticketGrantingTicketCookieGenerator;
    @Autowired
    @Qualifier("warnCookieGenerator")
    private ObjectProvider<CookieRetrievingCookieGenerator> warnCookieGenerator;
    @Autowired
    private CasConfigurationProperties casProperties;
    @Autowired
    @Qualifier("webApplicationServiceFactory")
    private ServiceFactory webApplicationServiceFactory;
    @Autowired
    @Qualifier("adaptiveAuthenticationPolicy")
    private AdaptiveAuthenticationPolicy adaptiveAuthenticationPolicy;
    @Autowired
    @Qualifier("centralAuthenticationService")
    private CentralAuthenticationService centralAuthenticationService;
    @Autowired
    @Qualifier("defaultAuthenticationSystemSupport")
    private AuthenticationSystemSupport authenticationSystemSupport;
    @Autowired
    @Qualifier("logoutManager")
    private LogoutManager logoutManager;
    @Autowired
    @Qualifier("defaultTicketRegistrySupport")
    private TicketRegistrySupport ticketRegistrySupport;
    @Autowired
    @Qualifier("rankedAuthenticationProviderWebflowEventResolver")
    private CasWebflowEventResolver rankedAuthenticationProviderWebflowEventResolver;
    @Autowired
    @Qualifier("authenticationServiceSelectionPlan")
    private AuthenticationServiceSelectionPlan authenticationRequestServiceSelectionStrategies;
    @Autowired
    @Qualifier("singleSignOnParticipationStrategy")
    private SingleSignOnParticipationStrategy webflowSingleSignOnParticipationStrategy;
    @Autowired
    @Qualifier("principalElectionStrategy")
    private PrincipalElectionStrategy principalElectionStrategy;


    public CasSupportActionsConfiguration() {
    }

    @Bean
    @RefreshScope
    public HandlerExceptionResolver errorHandlerResolver() {
        return new FlowExecutionExceptionResolver();
    }

    @ConditionalOnMissingBean(
            name = {"authenticationViaFormAction"}
    )
    @Bean
    @RefreshScope
    public Action authenticationViaFormAction() {
        return new InitialAuthenticationAction(this.initialAuthenticationAttemptWebflowEventResolver, this.serviceTicketRequestWebflowEventResolver, this.adaptiveAuthenticationPolicy);
    }

    @RefreshScope
    @ConditionalOnMissingBean(
            name = {"serviceAuthorizationCheck"}
    )
    @Bean
    public Action serviceAuthorizationCheck() {
        return new ServiceAuthorizationCheck(this.servicesManager, this.authenticationRequestServiceSelectionStrategies);
    }

    @RefreshScope
    @ConditionalOnMissingBean(
            name = {"sendTicketGrantingTicketAction"}
    )
    @Bean
    public Action sendTicketGrantingTicketAction() {
        return new SendTicketGrantingTicketAction(this.centralAuthenticationService, (CookieRetrievingCookieGenerator)this.ticketGrantingTicketCookieGenerator.getIfAvailable(), this.webflowSingleSignOnParticipationStrategy);
    }

    @RefreshScope
    @ConditionalOnMissingBean(
            name = {"createTicketGrantingTicketAction"}
    )
    @Bean
    public Action createTicketGrantingTicketAction() {
        return new CreateTicketGrantingTicketAction(this.centralAuthenticationService, this.authenticationSystemSupport, this.ticketRegistrySupport);
    }

    @RefreshScope
    @ConditionalOnMissingBean(
            name = {"setServiceUnauthorizedRedirectUrlAction"}
    )
    @Bean
    public Action setServiceUnauthorizedRedirectUrlAction() {
        return new SetServiceUnauthorizedRedirectUrlAction(this.servicesManager);
    }

    @RefreshScope
    @Bean
    @ConditionalOnMissingBean(
            name = {"logoutAction"}
    )
    public Action logoutAction() {
        return new LogoutAction(this.webApplicationServiceFactory, this.servicesManager, this.casProperties.getLogout());
    }

    @ConditionalOnMissingBean(
            name = {"initializeLoginAction"}
    )
    @Bean
    @RefreshScope
    public Action initializeLoginAction() {
        return new InitializeLoginAction(this.servicesManager);
    }

    @RefreshScope
    @Bean
    @Autowired
    @ConditionalOnMissingBean(
            name = {"initialFlowSetupAction"}
    )
    public Action initialFlowSetupAction(@Qualifier("argumentExtractor") final ArgumentExtractor argumentExtractor) {
        return new InitialFlowSetupAction(CollectionUtils.wrap(argumentExtractor), this.servicesManager, this.authenticationRequestServiceSelectionStrategies, (CookieRetrievingCookieGenerator)this.ticketGrantingTicketCookieGenerator.getIfAvailable(), (CookieRetrievingCookieGenerator)this.warnCookieGenerator.getIfAvailable(), this.casProperties);
    }

    @RefreshScope
    @Bean
    @ConditionalOnMissingBean(
            name = {"initialAuthenticationRequestValidationAction"}
    )
    public Action initialAuthenticationRequestValidationAction() {
        return new InitialAuthenticationRequestValidationAction(this.rankedAuthenticationProviderWebflowEventResolver);
    }

    @RefreshScope
    @Bean
    @ConditionalOnMissingBean(
            name = {"genericSuccessViewAction"}
    )
    public Action genericSuccessViewAction() {
        return new GenericSuccessViewAction(this.centralAuthenticationService, this.servicesManager, this.webApplicationServiceFactory, this.casProperties.getView().getDefaultRedirectUrl());
    }

    @RefreshScope
    @Bean
    @ConditionalOnMissingBean(
            name = {"redirectUnauthorizedServiceUrlAction"}
    )
    public Action redirectUnauthorizedServiceUrlAction() {
        return new RedirectUnauthorizedServiceUrlAction(this.servicesManager);
    }

    @Bean
    @RefreshScope
    @ConditionalOnMissingBean(
            name = {"generateServiceTicketAction"}
    )
    public Action generateServiceTicketAction() {
        return new GenerateServiceTicketAction(this.authenticationSystemSupport, this.centralAuthenticationService, this.ticketRegistrySupport, this.authenticationRequestServiceSelectionStrategies, this.servicesManager, this.principalElectionStrategy);
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"gatewayServicesManagementCheck"}
    )
    @RefreshScope
    public Action gatewayServicesManagementCheck() {
        return new GatewayServicesManagementCheck(this.servicesManager);
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"frontChannelLogoutAction"}
    )
    public Action frontChannelLogoutAction() {
        return new FrontChannelLogoutAction(this.logoutManager);
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"ticketGrantingTicketCheckAction"}
    )
    public Action ticketGrantingTicketCheckAction() {
        return new TicketGrantingTicketCheckAction(this.centralAuthenticationService);
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"terminateSessionAction"}
    )
    @RefreshScope
    public Action terminateSessionAction() {
        return new TerminateSessionAction(this.centralAuthenticationService, (CookieRetrievingCookieGenerator)this.ticketGrantingTicketCookieGenerator.getIfAvailable(), (CookieRetrievingCookieGenerator)this.warnCookieGenerator.getIfAvailable(), this.casProperties.getLogout());
    }

    @Bean
    public Action logoutViewSetupAction() {
        return new LogoutViewSetupAction(this.casProperties);
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"serviceWarningAction"}
    )
    @RefreshScope
    public Action serviceWarningAction() {
        return new ServiceWarningAction(this.centralAuthenticationService, this.authenticationSystemSupport, this.ticketRegistrySupport, (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), this.principalElectionStrategy);
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"mfaAvailableAction"}
    )
    @RefreshScope
    public Action mfaAvailableAction() {
        return new MultifactorAuthenticationAvailableAction();
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"mfaBypassAction"}
    )
    @RefreshScope
    public Action mfaBypassAction() {
        return new MultifactorAuthenticationBypassAction();
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"mfaFailureAction"}
    )
    @RefreshScope
    public Action mfaFailureAction() {
        return new MultifactorAuthenticationFailureAction(this.casProperties);
    }
}
