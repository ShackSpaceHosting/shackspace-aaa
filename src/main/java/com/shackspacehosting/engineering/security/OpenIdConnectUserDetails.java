package com.shackspacehosting.engineering.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class OpenIdConnectUserDetails implements UserDetails {

    private static final long serialVersionUID = 1L;

	final private String userId;
	final private String username;
	final private String email;
	final private String name;
	final private OAuth2AccessToken token;
    final private Map<String, Object> claimMap;
    final private String groupsPrefix;
    final private String rolesPrefix;

    public OpenIdConnectUserDetails(Map<String, Object> userInfo, OAuth2AccessToken token, String groupsPrefix, String rolesPrefix) {
        this.userId = userInfo.get("sub").toString();
        this.username = userInfo.get("preferred_username").toString();
        this.name = userInfo.get("name").toString();
        this.email = userInfo.get("email").toString();
        this.token = token;
        this.claimMap = userInfo;
        this.groupsPrefix = groupsPrefix;
        this.rolesPrefix = rolesPrefix;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

		List<GrantedAuthority> authoritiesList = new ArrayList<>();
		final List<String> roles = (List<String>)claimMap.get("roles");
		if(roles != null) {
			roles.forEach(roleName -> authoritiesList.add(new SimpleGrantedAuthority(rolesPrefix + roleName.toUpperCase())));
		}

		final List<String> groups = (List<String>)claimMap.get("groups");
		if(groups != null) {
			groups.forEach(groupName -> authoritiesList.add(new SimpleGrantedAuthority(groupsPrefix + groupName.toUpperCase())));
		}
		return authoritiesList;
    }

    public String getUserId() {
        return userId;
    }

    public OAuth2AccessToken getToken() {
        return token;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
