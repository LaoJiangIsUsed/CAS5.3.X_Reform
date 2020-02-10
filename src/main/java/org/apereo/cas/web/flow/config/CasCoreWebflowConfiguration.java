package org.apereo.cas.web.flow.config;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//



import java.util.LinkedHashSet;
import java.util.Set;
import javax.security.auth.login.AccountExpiredException;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.CredentialExpiredException;
import javax.security.auth.login.FailedLoginException;

import lombok.Generated;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.CipherExecutor;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.AuthenticationContextValidator;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.PrincipalException;
import org.apereo.cas.authentication.adaptive.UnauthorizedAuthenticationException;
import org.apereo.cas.authentication.adaptive.geo.GeoLocationService;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.exceptions.InvalidLoginLocationException;
import org.apereo.cas.authentication.exceptions.InvalidLoginTimeException;
import org.apereo.cas.authentication.principal.ResponseBuilderLocator;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.core.sso.SsoProperties;
import org.apereo.cas.configuration.model.core.util.EncryptionRandomizedSigningJwtCryptographyProperties;
import org.apereo.cas.configuration.model.webapp.WebflowProperties;
import org.apereo.cas.services.MultifactorAuthenticationProviderSelector;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.services.UnauthorizedServiceForPrincipalException;
import org.apereo.cas.ticket.UnsatisfiedAuthenticationPolicyException;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.util.cipher.WebflowConversationStateCipherExecutor;
import org.apereo.cas.web.flow.DefaultSingleSignOnParticipationStrategy;
import org.apereo.cas.web.flow.SingleSignOnParticipationStrategy;
import org.apereo.cas.web.flow.actions.AuthenticationExceptionHandlerAction;
import org.apereo.cas.web.flow.actions.CheckWebAuthenticationRequestAction;
import org.apereo.cas.web.flow.actions.ClearWebflowCredentialAction;
import org.apereo.cas.web.flow.actions.InjectResponseHeadersAction;
import org.apereo.cas.web.flow.actions.RedirectToServiceAction;
import org.apereo.cas.web.flow.authentication.GroovyScriptMultifactorAuthenticationProviderSelector;
import org.apereo.cas.web.flow.authentication.RankedMultifactorAuthenticationProviderSelector;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.CasWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.impl.InitialAuthenticationAttemptWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.impl.RankedAuthenticationProviderWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.impl.SelectiveAuthenticationProviderWebflowEventEventResolver;
import org.apereo.cas.web.flow.resolver.impl.ServiceTicketRequestWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.AuthenticationAttributeMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.GlobalMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.GroovyScriptMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.PredicatedPrincipalAttributeMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.PrincipalAttributeMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.RegisteredServiceMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.RegisteredServicePrincipalAttributeMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.RestEndpointMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.adaptive.AdaptiveMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.adaptive.TimedMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.request.RequestHeaderMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.request.RequestParameterMultifactorAuthenticationPolicyEventResolver;
import org.apereo.cas.web.flow.resolver.impl.mfa.request.RequestSessionAttributeMultifactorAuthenticationPolicyEventResolver;
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
import org.springframework.core.io.Resource;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.execution.Action;

@Configuration("casCoreWebflowConfiguration")
@EnableConfigurationProperties({CasConfigurationProperties.class})
public class CasCoreWebflowConfiguration {
    @Generated
    private static final Logger LOGGER = LoggerFactory.getLogger(CasCoreWebflowConfiguration.class);
    @Autowired
    @Qualifier("geoLocationService")
    private ObjectProvider<GeoLocationService> geoLocationService;
    @Autowired
    @Qualifier("authenticationContextValidator")
    private ObjectProvider<AuthenticationContextValidator> authenticationContextValidator;
    @Autowired
    @Qualifier("centralAuthenticationService")
    private ObjectProvider<CentralAuthenticationService> centralAuthenticationService;
    @Autowired
    @Qualifier("defaultAuthenticationSystemSupport")
    private ObjectProvider<AuthenticationSystemSupport> authenticationSystemSupport;
    @Autowired
    @Qualifier("defaultTicketRegistrySupport")
    private ObjectProvider<TicketRegistrySupport> ticketRegistrySupport;
    @Autowired
    @Qualifier("webApplicationResponseBuilderLocator")
    private ResponseBuilderLocator responseBuilderLocator;
    @Autowired
    @Qualifier("servicesManager")
    private ObjectProvider<ServicesManager> servicesManager;
    @Autowired
    @Qualifier("warnCookieGenerator")
    private ObjectProvider<CookieGenerator> warnCookieGenerator;
    @Autowired
    private CasConfigurationProperties casProperties;
    @Autowired
    @Qualifier("multifactorAuthenticationProviderSelector")
    private MultifactorAuthenticationProviderSelector multifactorAuthenticationProviderSelector;
    @Autowired
    @Qualifier("authenticationServiceSelectionPlan")
    private ObjectProvider<AuthenticationServiceSelectionPlan> authenticationServiceSelectionPlan;
    @Autowired
    @Qualifier("registeredServiceAccessStrategyEnforcer")
    private AuditableExecution registeredServiceAccessStrategyEnforcer;

    public CasCoreWebflowConfiguration() {
    }

    @ConditionalOnMissingBean(
            name = {"adaptiveAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver adaptiveAuthenticationPolicyWebflowEventResolver() {
        return new AdaptiveMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties, (GeoLocationService)this.geoLocationService.getIfAvailable());
    }

    @ConditionalOnMissingBean(
            name = {"timedAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver timedAuthenticationPolicyWebflowEventResolver() {
        return new TimedMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"principalAttributeAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver principalAttributeAuthenticationPolicyWebflowEventResolver() {
        return new PrincipalAttributeMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"predicatedPrincipalAttributeMultifactorAuthenticationPolicyEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver predicatedPrincipalAttributeMultifactorAuthenticationPolicyEventResolver() {
        return new PredicatedPrincipalAttributeMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"authenticationAttributeAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver authenticationAttributeAuthenticationPolicyWebflowEventResolver() {
        return new AuthenticationAttributeMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"multifactorAuthenticationProviderSelector"}
    )
    @Bean
    @RefreshScope
    public MultifactorAuthenticationProviderSelector multifactorAuthenticationProviderSelector() {
        Resource script = this.casProperties.getAuthn().getMfa().getProviderSelectorGroovyScript();
        return (MultifactorAuthenticationProviderSelector)(script != null ? new GroovyScriptMultifactorAuthenticationProviderSelector(script) : new RankedMultifactorAuthenticationProviderSelector());
    }

    @ConditionalOnMissingBean(
            name = {"initialAuthenticationAttemptWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasDelegatingWebflowEventResolver initialAuthenticationAttemptWebflowEventResolver() {
        InitialAuthenticationAttemptWebflowEventResolver r = new InitialAuthenticationAttemptWebflowEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.registeredServiceAccessStrategyEnforcer);
        r.addDelegate(this.adaptiveAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.timedAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.globalAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.requestParameterAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.requestHeaderAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.requestSessionAttributeAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.restEndpointAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.groovyScriptAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.registeredServicePrincipalAttributeAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.predicatedPrincipalAttributeMultifactorAuthenticationPolicyEventResolver());
        r.addDelegate(this.principalAttributeAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.authenticationAttributeAuthenticationPolicyWebflowEventResolver());
        r.addDelegate(this.registeredServiceAuthenticationPolicyWebflowEventResolver());
        r.setSelectiveResolver(this.selectiveAuthenticationProviderWebflowEventResolver());
        return r;
    }

    @ConditionalOnMissingBean(
            name = {"restEndpointAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver restEndpointAuthenticationPolicyWebflowEventResolver() {
        return new RestEndpointMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"serviceTicketRequestWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver serviceTicketRequestWebflowEventResolver() {
        return new ServiceTicketRequestWebflowEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.registeredServiceAccessStrategyEnforcer, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"globalAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver globalAuthenticationPolicyWebflowEventResolver() {
        return new GlobalMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"groovyScriptAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver groovyScriptAuthenticationPolicyWebflowEventResolver() {
        return new GroovyScriptMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"selectiveAuthenticationProviderWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver selectiveAuthenticationProviderWebflowEventResolver() {
        return new SelectiveAuthenticationProviderWebflowEventEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector);
    }

    @ConditionalOnMissingBean(
            name = {"requestParameterAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver requestParameterAuthenticationPolicyWebflowEventResolver() {
        return new RequestParameterMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"requestHeaderAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver requestHeaderAuthenticationPolicyWebflowEventResolver() {
        return new RequestHeaderMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"requestSessionAttributeAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver requestSessionAttributeAuthenticationPolicyWebflowEventResolver() {
        return new RequestSessionAttributeMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, this.casProperties);
    }

    @ConditionalOnMissingBean(
            name = {"registeredServicePrincipalAttributeAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver registeredServicePrincipalAttributeAuthenticationPolicyWebflowEventResolver() {
        return new RegisteredServicePrincipalAttributeMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector);
    }

    @ConditionalOnMissingBean(
            name = {"registeredServiceAuthenticationPolicyWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver registeredServiceAuthenticationPolicyWebflowEventResolver() {
        return new RegisteredServiceMultifactorAuthenticationPolicyEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector);
    }

    @ConditionalOnMissingBean(
            name = {"rankedAuthenticationProviderWebflowEventResolver"}
    )
    @Bean
    @RefreshScope
    public CasWebflowEventResolver rankedAuthenticationProviderWebflowEventResolver() {
        return new RankedAuthenticationProviderWebflowEventResolver((AuthenticationSystemSupport)this.authenticationSystemSupport.getIfAvailable(), (CentralAuthenticationService)this.centralAuthenticationService.getIfAvailable(), (ServicesManager)this.servicesManager.getIfAvailable(), (TicketRegistrySupport)this.ticketRegistrySupport.getIfAvailable(), (CookieGenerator)this.warnCookieGenerator.getIfAvailable(), (AuthenticationServiceSelectionPlan)this.authenticationServiceSelectionPlan.getIfAvailable(), this.multifactorAuthenticationProviderSelector, (AuthenticationContextValidator)this.authenticationContextValidator.getIfAvailable(), this.initialAuthenticationAttemptWebflowEventResolver());
    }

    @Bean
    @RefreshScope
    public CipherExecutor webflowCipherExecutor() {
        WebflowProperties webflow = this.casProperties.getWebflow();
        EncryptionRandomizedSigningJwtCryptographyProperties crypto = webflow.getCrypto();
        boolean enabled = crypto.isEnabled();
        if (!enabled && StringUtils.isNotBlank(crypto.getEncryption().getKey()) && StringUtils.isNotBlank(crypto.getSigning().getKey())) {
            LOGGER.warn("Webflow encryption/signing is not enabled explicitly in the configuration, yet signing/encryption keys are defined for operations. CAS will proceed to enable the webflow encryption/signing functionality.");
            enabled = true;
        }

        if (enabled) {
            return new WebflowConversationStateCipherExecutor(crypto.getEncryption().getKey(), crypto.getSigning().getKey(), crypto.getAlg(), crypto.getSigning().getKeySize(), crypto.getEncryption().getKeySize());
        } else {
            LOGGER.warn("Webflow encryption/signing is turned off. This MAY NOT be safe in a production environment. Consider using other choices to handle encryption, signing and verification of webflow state.");
            return CipherExecutor.noOp();
        }
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"clearWebflowCredentialsAction"}
    )
    @RefreshScope
    public Action clearWebflowCredentialsAction() {
        return new ClearWebflowCredentialAction();
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"checkWebAuthenticationRequestAction"}
    )
    @RefreshScope
    public Action checkWebAuthenticationRequestAction() {
        return new CheckWebAuthenticationRequestAction(this.casProperties.getAuthn().getMfa().getContentType());
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"redirectToServiceAction"}
    )
    @RefreshScope
    public Action redirectToServiceAction() {
        return new RedirectToServiceAction(this.responseBuilderLocator);
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"injectResponseHeadersAction"}
    )
    @RefreshScope
    public Action injectResponseHeadersAction() {
        return new InjectResponseHeadersAction(this.responseBuilderLocator);
    }

    @Bean
    @ConditionalOnMissingBean(
            name = {"singleSignOnParticipationStrategy"}
    )
    @RefreshScope
    public SingleSignOnParticipationStrategy singleSignOnParticipationStrategy() {
        SsoProperties sso = this.casProperties.getSso();
        return new DefaultSingleSignOnParticipationStrategy((ServicesManager)this.servicesManager.getIfAvailable(), sso.isCreateSsoCookieOnRenewAuthn(), sso.isRenewAuthnEnabled());
    }

    @ConditionalOnMissingBean(
            name = {"authenticationExceptionHandler"}
    )
    @Bean
    public Action authenticationExceptionHandler() {
        return new AuthenticationExceptionHandlerAction(this.handledAuthenticationExceptions());
    }

    @RefreshScope
    @Bean
    public Set<Class<? extends Throwable>> handledAuthenticationExceptions() {
        Set<Class<? extends Throwable>> errors = new LinkedHashSet();
        errors.add(AccountLockedException.class);
        errors.add(CredentialExpiredException.class);
        errors.add(AccountExpiredException.class);
        errors.add(AccountDisabledException.class);
        errors.add(InvalidLoginLocationException.class);
        errors.add(AccountPasswordMustChangeException.class);
        errors.add(InvalidLoginTimeException.class);
        errors.add(AccountNotFoundException.class);
        errors.add(FailedLoginException.class);
        errors.add(UnauthorizedServiceForPrincipalException.class);
        errors.add(PrincipalException.class);
        errors.add(UnsatisfiedAuthenticationPolicyException.class);
        errors.add(UnauthorizedAuthenticationException.class);
        errors.addAll(this.casProperties.getAuthn().getExceptions().getExceptions());
        return errors;
    }
}
