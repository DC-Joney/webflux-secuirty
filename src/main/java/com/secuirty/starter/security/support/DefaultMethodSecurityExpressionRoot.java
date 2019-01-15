package com.secuirty.starter.security.support;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Extended expression root object which contains extra method-specific functionality.
 *
 * @author Luke Taylor
 * @since 3.0
 */
class DefaultMethodSecurityExpressionRoot extends SecurityExpressionRoot implements
        MethodSecurityExpressionOperations {
    private Object filterObject;
    private Object returnObject;
    private Object target;

    private RoleHierarchy roleHierarchy;

    private String defaultRolePrefix = "ROLE_";

    private Set<String> roles;


    DefaultMethodSecurityExpressionRoot(Authentication a) {
        super(a);
    }

    @Override
    public void setDefaultRolePrefix(String defaultRolePrefix) {
        this.defaultRolePrefix = defaultRolePrefix;
    }

    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    public Object getFilterObject() {
        return filterObject;
    }

    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    public Object getReturnObject() {
        return returnObject;
    }

    void setThis(Object target) {
        this.target = target;
    }

    public Object getThis() {
        return target;
    }

    public final boolean hasRoles(String role) {
        return hasAnyRole(role.replace("\"",""));
    }

    public final boolean hasAnyRoles(String... roles) {
        return hasAnyAuthorityName(defaultRolePrefix, roles);
    }

    @Override
    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }

    private boolean hasAnyAuthorityName(String prefix, String... roles) {
        Set<String> roleSet = getAuthoritySet();

        for (String role : roles) {
            String defaultedRole = getRoleWithDefaultPrefix(prefix, role);
            if (roleSet.contains(defaultedRole)) {
                return true;
            }
        }

        return false;
    }


    private static String getRoleWithDefaultPrefix(String defaultRolePrefix, String role) {
        if (role == null) {
            return role;
        }
        if (defaultRolePrefix == null || defaultRolePrefix.length() == 0) {
            return role;
        }
        if (role.startsWith(defaultRolePrefix)) {
            return role;
        }
        return defaultRolePrefix + role;
    }


    private Set<String> getAuthoritySet() {
        if (roles == null) {
            this.roles = new HashSet<>();
            Collection<? extends GrantedAuthority> userAuthorities = authentication
                    .getAuthorities();

            if (roleHierarchy != null) {
                userAuthorities = roleHierarchy
                        .getReachableGrantedAuthorities(userAuthorities);
            }

            this.roles = AuthorityUtils.authorityListToSet(userAuthorities);
        }

        return this.roles;
    }


}

