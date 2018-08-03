package com.shackspacehosting.engineering.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

import java.util.Arrays;

@Configuration
@EnableOAuth2Client
public class OpenIdConnectConfig {
    @Value("${openid.connect.clientId}")
    private String clientId;

    @Value("${openid.connect.clientSecret}")
    private String clientSecret;

    @Value("${openid.connect.accessTokenUri:https://kc-sso.pods.origin.shackspacehosting.com/auth/realms/ssh/protocol/openid-connect/token}")
    private String accessTokenUri;

    @Value("${openid.connect.userAuthorizationUri:https://kc-sso.pods.origin.shackspacehosting.com/auth/realms/ssh/protocol/openid-connect/auth}")
    private String userAuthorizationUri;

    // Example: https://openshift-pvmanager-devops.pods.origin.shackspacehosting.com/login
	@Value("${openid.connect.redirectUri:}")
    private String redirectUri;

    @Value("${openid.groups.claim:groups}")
    private String groupsClaim;

    @Value("${openid.roles.claim:roles}")
    private String rolesClaim;

    @Bean
    public OAuth2ProtectedResourceDetails openIdConfigTemplate() {
        final AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthorizationUri);
        details.setScope(Arrays.asList("openid", "email", "profile", rolesClaim, groupsClaim));
        if(redirectUri != null && !redirectUri.isEmpty()) {
            details.setPreEstablishedRedirectUri(redirectUri);
        }
        details.setUseCurrentUri(true);

        return details;
    }

    @Bean
    public OAuth2RestTemplate openIdConnectTemplate(final OAuth2ClientContext clientContext) {
        final OAuth2RestTemplate template = new OAuth2RestTemplate(openIdConfigTemplate(), clientContext);
        return template;
    }

}
