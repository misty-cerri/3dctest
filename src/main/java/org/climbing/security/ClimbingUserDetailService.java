package org.climbing.security;

import java.util.ArrayList;
import java.util.List;

import org.climbing.domain.Role;
import org.climbing.domain.User;
import org.climbing.repo.UserDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component("climbingUserDetailService")
public class ClimbingUserDetailService implements UserDetailsService {

	@Autowired
	UserDao userDao;
	
	@Transactional
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {

		User u = null;
		
		try {
			
			System.out.println("Login for " + username);
			u = userDao.findByUsername(username);
			
			List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
			if(u.getRoles() != null) {
				for(Role r: u.getRoles()) {
					if(r.getId() == Role.ADMIN) {
						authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
						System.out.println(username + " is admin");
					} else if(r.getId() == Role.USER) {
						authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
						System.out.println(username + " is user");
					}
				}
			}
			
			return new ClimbingUserDetails(u, authorities);
			
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Auth failed for " + username + ": " + e.getMessage());
			return null;
		}
	}
}
