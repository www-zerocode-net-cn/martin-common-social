package com.java2e.martin.common.social.properties;

import lombok.Data;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author 狮少
 * @version 1.0
 * @date 2021/8/4
 * @describtion SocialOAuth2ClientProperties
 * @since 1.0
 */
@Data
@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class SocialOAuth2ClientProperties {

    private List<String> ignoreUrls = new ArrayList<>();

    /**
     * OAuth provider details.
     */
    private final Map<String, SocialOAuth2ClientProperties.Provider> provider = new HashMap<>();

    /**
     * OAuth client registrations.
     */
    private final Map<String, SocialOAuth2ClientProperties.Registration> registration = new HashMap<>();



    @PostConstruct
    public void validate() {
        getRegistration().values().forEach(this::validateRegistration);
    }

    private void validateRegistration(SocialOAuth2ClientProperties.Registration registration) {
        if (!StringUtils.hasText(registration.getClientId())) {
            throw new IllegalStateException("Client id must not be empty.");
        }
    }

    /**
     * A single client registration.
     */
    public static class Registration {

        /**
         * Reference to the OAuth 2.0 provider to use. May reference an element from the
         * 'provider' property or used one of the commonly used providers (google, github,
         * facebook, okta).
         */
        private String provider;

        /**
         * Client ID for the registration.
         */
        private String clientId;

        /**
         * Client secret of the registration.
         */
        private String clientSecret;

        /**
         * Client authentication method. May be left blank when using a pre-defined
         * provider.
         */
        private String clientAuthenticationMethod;

        /**
         * Authorization grant type. May be left blank when using a pre-defined provider.
         */
        private String authorizationGrantType;

        /**
         * Redirect URI. May be left blank when using a pre-defined provider.
         */
        private String redirectUri;

        /**
         * Authorization scopes. May be left blank when using a pre-defined provider.
         */
        private Set<String> scope;

        /**
         * Client name. May be left blank when using a pre-defined provider.
         */
        private String clientName;

        public String getProvider() {
            return this.provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getClientId() {
            return this.clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return this.clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getClientAuthenticationMethod() {
            return this.clientAuthenticationMethod;
        }

        public void setClientAuthenticationMethod(String clientAuthenticationMethod) {
            this.clientAuthenticationMethod = clientAuthenticationMethod;
        }

        public String getAuthorizationGrantType() {
            return this.authorizationGrantType;
        }

        public void setAuthorizationGrantType(String authorizationGrantType) {
            this.authorizationGrantType = authorizationGrantType;
        }

        public String getRedirectUri() {
            return this.redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public Set<String> getScope() {
            return this.scope;
        }

        public void setScope(Set<String> scope) {
            this.scope = scope;
        }

        public String getClientName() {
            return this.clientName;
        }

        public void setClientName(String clientName) {
            this.clientName = clientName;
        }

    }

    public static class Provider {

        /**
         * Authorization URI for the provider.
         */
        private String authorizationUri;

        /**
         * Token URI for the provider.
         */
        private String tokenUri;

        /**
         * User info URI for the provider.
         */
        private String userInfoUri;

        /**
         * User info authentication method for the provider.
         */
        private String userInfoAuthenticationMethod;

        /**
         * Name of the attribute that will be used to extract the username from the call
         * to 'userInfoUri'.
         */
        private String userNameAttribute;

        /**
         * JWK set URI for the provider.
         */
        private String jwkSetUri;

        /**
         * URI that can either be an OpenID Connect discovery endpoint or an OAuth 2.0
         * Authorization Server Metadata endpoint defined by RFC 8414.
         */
        private String issuerUri;

        public String getAuthorizationUri() {
            return this.authorizationUri;
        }

        public void setAuthorizationUri(String authorizationUri) {
            this.authorizationUri = authorizationUri;
        }

        public String getTokenUri() {
            return this.tokenUri;
        }

        public void setTokenUri(String tokenUri) {
            this.tokenUri = tokenUri;
        }

        public String getUserInfoUri() {
            return this.userInfoUri;
        }

        public void setUserInfoUri(String userInfoUri) {
            this.userInfoUri = userInfoUri;
        }

        public String getUserInfoAuthenticationMethod() {
            return this.userInfoAuthenticationMethod;
        }

        public void setUserInfoAuthenticationMethod(String userInfoAuthenticationMethod) {
            this.userInfoAuthenticationMethod = userInfoAuthenticationMethod;
        }

        public String getUserNameAttribute() {
            return this.userNameAttribute;
        }

        public void setUserNameAttribute(String userNameAttribute) {
            this.userNameAttribute = userNameAttribute;
        }

        public String getJwkSetUri() {
            return this.jwkSetUri;
        }

        public void setJwkSetUri(String jwkSetUri) {
            this.jwkSetUri = jwkSetUri;
        }

        public String getIssuerUri() {
            return this.issuerUri;
        }

        public void setIssuerUri(String issuerUri) {
            this.issuerUri = issuerUri;
        }

    }

}
