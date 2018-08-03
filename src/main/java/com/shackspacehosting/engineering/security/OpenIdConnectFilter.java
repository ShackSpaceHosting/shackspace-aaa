package com.shackspacehosting.engineering.security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;

public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {
    @Value("${openid.connect.clientId}")
    private String clientId;

    @Value("${openid.connect.issuer:https://kc-sso.pods.origin.shackspacehosting.com/auth/realms/ssh}")
    private String issuer;

    @Value("${openid.connect.caurl:https://kc-sso.pods.origin.shackspacehosting.com/auth/realms/ssh/protocol/openid-connect/certs}")
    private String jwkUrl;

    @Value("${openid.groups.prefix:}")
    private String groupsPrefix;

    @Value("${openid.roles.prefix:}")
    private String rolesPrefix;

    public OAuth2RestOperations restTemplate;

    public OpenIdConnectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
        setAuthenticationManager(new NoopAuthenticationManager());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        OAuth2AccessToken accessToken;
        try {
            accessToken = restTemplate.getAccessToken();
        } catch (final OAuth2Exception e) {
            throw new BadCredentialsException("Could not obtain access token", e);
        }
        try {
            final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
            String kid = JwtHelper.headers(idToken)
                .get("kid");
            final Jwt tokenDecoded = JwtHelper.decodeAndVerify(idToken, verifier(kid));
            final Map<String, Object> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
            verifyClaims(authInfo);
            final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(authInfo, accessToken, groupsPrefix, rolesPrefix);
            return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        } catch (final Exception e) {
            throw new BadCredentialsException("Could not obtain user details from token", e);
        }

    }

    public void verifyClaims(Map claims) {
        int exp = (int) claims.get("exp");
        Date expireDate = new Date(exp * 1000L);
        Date now = new Date();
        if (expireDate.before(now) || !claims.get("iss").equals(issuer) || !claims.get("aud").equals(clientId)) {
            throw new RuntimeException("Invalid claims");
        }
    }


    private RsaVerifier verifier(String kid) throws Exception {
        JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
        Jwk jwk = provider.get(kid);
        return new RsaVerifier((RSAPublicKey) jwk.getPublicKey());
    }

    public void setRestTemplate(OAuth2RestTemplate restTemplate2) {
        restTemplate = restTemplate2;

    }

    private static class NoopAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }

    }
}
