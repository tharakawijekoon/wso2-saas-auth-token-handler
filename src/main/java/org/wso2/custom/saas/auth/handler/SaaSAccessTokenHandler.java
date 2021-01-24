package org.wso2.custom.saas.auth.handler;

import org.apache.catalina.connector.Request;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ProvisioningServiceProviderType;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ThreadLocalProvisioningServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.isAuthHeaderMatch;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;
import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER;

public class SaaSAccessTokenHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(SaaSAccessTokenHandler.class);
    private final String OAUTH_HEADER = "Bearer";
    private final String CONSUMER_KEY = "consumer-key";
    private final String SERVICE_PROVIDER = "serviceProvider";
    private final String SERVICE_PROVIDER_TENANT_DOMAIN = "serviceProviderTenantDomain";
    private final String SCIM_ME_ENDPOINT_URI = "scim2/me";
    private final String SAAS_SP_TENANT_DOMAIN = "SaaSSPTenantDomain";

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        if (authenticationRequest != null) {

            String authorizationHeader = authenticationRequest.getHeader(HttpHeaders.AUTHORIZATION);
            if (StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader.startsWith(OAUTH_HEADER)) {
                String accessToken = null;
                String[] bearerToken = authorizationHeader.split(" ");
                if (bearerToken.length == 2) {
                    accessToken = bearerToken[1];
                }

                OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
                OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
                OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();
                token.setIdentifier(accessToken);
                token.setTokenType(OAUTH_HEADER);
                requestDTO.setAccessToken(token);

                //TODO: If these values are not set, validation will fail giving an NPE. Need to see why that happens
                OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                        TokenValidationContextParam();
                contextParam.setKey("dummy");
                contextParam.setValue("dummy");

                OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams =
                        new OAuth2TokenValidationRequestDTO.TokenValidationContextParam[1];
                contextParams[0] = contextParam;
                requestDTO.setContext(contextParams);

                OAuth2ClientApplicationDTO clientApplicationDTO;
                try {
                    PrivilegedCarbonContext.startTenantFlow();
                    PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
                    carbonContext.setTenantDomain(readClearSaaSSPTenantDomainThreadLocal());
                    clientApplicationDTO = oAuth2TokenValidationService
                            .findOAuthConsumerIfTokenIsValid
                                    (requestDTO);
                } finally {
                    PrivilegedCarbonContext.endTenantFlow();
                }
                OAuth2TokenValidationResponseDTO responseDTO = clientApplicationDTO.getAccessTokenValidationResponse();

                if (!responseDTO.isValid()) {
                    return authenticationResult;
                }

                if (!isTokenBindingValid(messageContext, responseDTO.getTokenBinding(),
                        clientApplicationDTO.getConsumerKey(), accessToken)) {
                    return authenticationResult;
                }

                authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);

                if (StringUtils.isNotEmpty(responseDTO.getAuthorizedUser())) {
                    User user = new User();
                    String tenantAwareUsername =
                            MultitenantUtils.getTenantAwareUsername(responseDTO.getAuthorizedUser());
                    user.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUsername));
                    user.setUserStoreDomain(UserCoreUtil.extractDomainFromName(tenantAwareUsername));
                    user.setTenantDomain(MultitenantUtils.getTenantDomain(responseDTO.getAuthorizedUser()));
                    authenticationContext.setUser(user);
                }

                authenticationContext.addParameter(CONSUMER_KEY, clientApplicationDTO.getConsumerKey());
                authenticationContext.addParameter(OAUTH2_ALLOWED_SCOPES, responseDTO.getScope());
                authenticationContext.addParameter(OAUTH2_VALIDATE_SCOPE,
                        AuthConfigurationUtil.getInstance().isScopeValidationEnabled());
                String serviceProvider = null;
                try {
                    serviceProvider =
                            OAuth2Util.getServiceProvider(clientApplicationDTO.getConsumerKey()).getApplicationName();
                } catch (IdentityOAuth2Exception e) {
                    log.error("Error occurred while getting the Service Provider by Consumer key: "
                            + clientApplicationDTO.getConsumerKey());
                }

                String serviceProviderTenantDomain = null;
                try {
                    serviceProviderTenantDomain =
                            OAuth2Util.getTenantDomainOfOauthApp(clientApplicationDTO.getConsumerKey());
                } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
                    log.error("Error occurred while getting the OAuth App tenantDomain by Consumer key: "
                            + clientApplicationDTO.getConsumerKey());
                }

                if (serviceProvider != null) {
                    authenticationContext.addParameter(SERVICE_PROVIDER, serviceProvider);
                    if (serviceProviderTenantDomain != null) {
                        authenticationContext.addParameter(SERVICE_PROVIDER_TENANT_DOMAIN, serviceProviderTenantDomain);
                    }

                    MDC.put(SERVICE_PROVIDER, serviceProvider);
                    // Set OAuth service provider details to be consumed by the provisioning framework.
                    setProvisioningServiceProviderThreadLocal(clientApplicationDTO.getConsumerKey(),
                            serviceProviderTenantDomain);
                }
            }
        }
        return authenticationResult;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {

        return "SaaSAuthentication";
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {

        return true;
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return getPriority(messageContext, 24);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        return isAuthHeaderMatch(messageContext, OAUTH_HEADER)
                && OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()
                && isSaaSAppCrossTenantCall(messageContext);
    }

    private boolean isSaaSAppCrossTenantCall(MessageContext messageContext) {

        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        if (authenticationContext.getAuthenticationRequest() != null) {
            String authorizationHeader = authenticationContext.getAuthenticationRequest()
                        .getHeader(HttpHeaders.AUTHORIZATION);
            if (StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader.startsWith(OAUTH_HEADER)) {
                String accessToken = null;
                String[] bearerToken = authorizationHeader.split(" ");
                if (bearerToken.length == 2) {
                    accessToken = bearerToken[1];
                    try {
                        AccessTokenDO accessTokenDO = OAuth2Util.findAccessToken(accessToken, false);
                        ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(accessTokenDO.getConsumerKey());
                        String spTenantDomain = serviceProvider.getOwner().getTenantDomain();
                        if (serviceProvider.isSaasApp() && isCrossTenant(spTenantDomain)) {
                            setSaaSSPTenantDomainThreadLocal(spTenantDomain);
                            return true;
                        }
                    } catch (Exception e) {
                        // Access token not found in the system.
                        if (log.isDebugEnabled()) {
                            log.debug("Error occurred while getting the SaaS App tenantDomain by Consumer key", e);
                        }
                        return false;
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Not a SaaS App or a cross tenant API call");
        }
        return false;
    }

    private boolean isCrossTenant(String spTenantDomain) {
        return !getTenantDomain().equals(spTenantDomain);
    }

    private String getTenantDomain() {
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    private void setSaaSSPTenantDomainThreadLocal(String spTenantDomain) {
        if (StringUtils.isNotBlank(spTenantDomain)) {
            IdentityUtil.threadLocalProperties.get().put(SAAS_SP_TENANT_DOMAIN, spTenantDomain);
            if (log.isDebugEnabled()) {
                log.debug("SaaS SP tenant domain : " + spTenantDomain + " is added to thread local.");
            }
        }
    }

    private String readClearSaaSSPTenantDomainThreadLocal() {
        if (IdentityUtil.threadLocalProperties.get().get(SAAS_SP_TENANT_DOMAIN) != null) {
            String spTenantDomain = (String) IdentityUtil.threadLocalProperties.get().get(SAAS_SP_TENANT_DOMAIN);
            IdentityUtil.threadLocalProperties.get().remove(SAAS_SP_TENANT_DOMAIN);
            return spTenantDomain;
        }
        return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
    }

    /**
     * Validate access token binding value.
     *
     * @param messageContext message context.
     * @param tokenBinding token binding.
     * @param clientId OAuth2 client id.
     * @param accessToken Bearer token from request.
     * @return true if token binding is valid.
     */
    private boolean isTokenBindingValid(MessageContext messageContext, TokenBinding tokenBinding, String clientId,
                                        String accessToken) {

        if (tokenBinding == null || StringUtils.isBlank(tokenBinding.getBindingReference())) {
            return true;
        }

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Failed to retrieve application information by client id: " + clientId, e);
            return false;
        }

        Request authenticationRequest =
                ((AuthenticationContext) messageContext).getAuthenticationRequest().getRequest();
        if (!oAuthAppDO.isTokenBindingValidationEnabled()) {
            if (authenticationRequest.getRequestURI().toLowerCase().endsWith(SCIM_ME_ENDPOINT_URI) &&
                    isSSOSessionBasedTokenBinding(tokenBinding.getBindingType())) {
                setCurrentSessionIdThreadLocal(getTokenBindingValueFromAccessToken(accessToken));
            }
            return true;
        }

        if (OAuth2Util.isValidTokenBinding(tokenBinding, authenticationRequest)) {
            if (authenticationRequest.getRequestURI().toLowerCase().endsWith(SCIM_ME_ENDPOINT_URI) &&
                    isSSOSessionBasedTokenBinding(tokenBinding.getBindingType())) {
                setCurrentSessionIdThreadLocal(tokenBinding.getBindingValue());
            }
            return true;
        }
        return false;
    }

    /**
     * Get the token binding value which corresponds to the current session identifier from the token when
     * SSO-session-based token binding is enabled.
     *
     * @param accessToken   Bearer token from request.
     * @return Token binding value.
     */
    private String getTokenBindingValueFromAccessToken(String accessToken) {

        String tokenBindingValue = null;
        try {
            AccessTokenDO accessTokenDO = OAuth2Util.findAccessToken(accessToken, false);
            if (accessTokenDO != null) {
                if (accessTokenDO.getTokenBinding() != null &&
                        StringUtils.isNotBlank(accessTokenDO.getTokenBinding().getBindingValue()) &&
                        isSSOSessionBasedTokenBinding(accessTokenDO.getTokenBinding().getBindingType())) {
                    tokenBindingValue = accessTokenDO.getTokenBinding().getBindingValue();
                }
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while getting the access token from the token identifier", e);
        }
        return tokenBindingValue;
    }

    /**
     * Set token binding value which corresponds to the current session id to a thread local to be used down the flow.
     * @param tokenBindingValue     Token Binding value.
     */
    private void setCurrentSessionIdThreadLocal(String tokenBindingValue) {

        if (StringUtils.isNotBlank(tokenBindingValue)) {
            IdentityUtil.threadLocalProperties.get().put(Constants.CURRENT_SESSION_IDENTIFIER, tokenBindingValue);
            if (log.isDebugEnabled()) {
                log.debug("Current session identifier: " + tokenBindingValue + " is added to thread local.");
            }
        }
    }

    /**
     * Check whether the token binding type is 'sso-session'.
     * @param tokenBindingType  Type of the token binding.
     * @return True if 'sso-session', false otherwise.
     */
    private boolean isSSOSessionBasedTokenBinding(String tokenBindingType) {

        return SSO_SESSION_BASED_TOKEN_BINDER.equals(tokenBindingType);
    }

    /**
     * Set the service provider details to a thread local variable to be consumed by the provisioning framework.
     *
     * @param oauthAppConsumerKey           Client ID of the OAuth client application.
     * @param serviceProviderTenantDomain   Tenant Domain of the OAuth application.
     */
    private void setProvisioningServiceProviderThreadLocal(String oauthAppConsumerKey,
                                                           String serviceProviderTenantDomain) {

        if (serviceProviderTenantDomain != null) {
            ThreadLocalProvisioningServiceProvider provisioningServiceProvider =
                    new ThreadLocalProvisioningServiceProvider();
            provisioningServiceProvider.setServiceProviderName(oauthAppConsumerKey);
            provisioningServiceProvider.setServiceProviderType(ProvisioningServiceProviderType.OAUTH);
            provisioningServiceProvider.setTenantDomain(serviceProviderTenantDomain);
            IdentityApplicationManagementUtil.setThreadLocalProvisioningServiceProvider(provisioningServiceProvider);
        }
    }
}
