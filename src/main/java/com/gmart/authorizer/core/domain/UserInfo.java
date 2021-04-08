/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.domain;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 3 avr. 2021
 **/
@Entity
@Table(name = "user")
@Data
@EqualsAndHashCode(callSuper=false)
public class UserInfo extends BaseIdEntity implements UserDetails, Serializable {

	/**
	 *
	 */
	private static final long serialVersionUID = -3659552125908727910L;

	@Column(unique = true, nullable = false)
	private String username;

	@Column(unique = true, nullable = false)
	private String email;

	@JsonIgnore
	private String password;

	@Column(name = "IS_ACCOUNT_NON_EXPIRED")
	private boolean isAccountNonExpired = true;

	@Column(name = "IS_ACCOUNT_NON_LOCKED")
	private boolean isAccountNonLocked = true;

	@Column(name = "IS_CREDENTIALS_NON_EXPIRED")
	private boolean isCredentialsNonExpired = true;

	@Column(name = "IS_ENABLED")
	private boolean isEnabled = true;

	@OneToMany(fetch = FetchType.EAGER, cascade = { CascadeType.ALL })
	@JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"), inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
	private Set<Role> roles = new HashSet<>();

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

		getRoles().forEach(role -> {
			grantedAuthorities.add(new SimpleGrantedAuthority(role.getRoleName()));
			role.getPermissions().forEach(permission -> {
				grantedAuthorities.add(new SimpleGrantedAuthority(permission.getPermissionName()));
			});

		});
		return grantedAuthorities;
	}
}
