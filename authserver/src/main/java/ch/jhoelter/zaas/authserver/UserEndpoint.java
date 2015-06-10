package ch.jhoelter.zaas.authserver;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by jet on 29/04/15.
 */
@RestController
@EnableResourceServer
public class UserEndpoint {

    @RequestMapping("/user")
    @ResponseBody
    public Map<String, Object> user(Principal user) {
        return Collections.<String, Object> singletonMap("name", user.getName());
    }

    @RequestMapping("/user-details")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public Map<String, Object> userDetails(Principal user) {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        map.put("name", user.getName());
        map.put("roles", AuthorityUtils.authorityListToSet(((Authentication) user)
                .getAuthorities()));
        return map;
    }

}
