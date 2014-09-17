/**
 * This file is part of Everit - CAS authentication.
 *
 * Everit - CAS authentication is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - CAS authentication is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - CAS authentication.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.authentication.cas.internal;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionActivationListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.authentication.cas.CasAuthenticationConstants;
import org.everit.osgi.authentication.cas.CasHttpSessionRegistry;
import org.osgi.framework.Constants;

@Component(name = CasAuthenticationConstants.SERVICE_FACTORYPID_CAS_HTTP_SESSION_REGISTRY, metatype = true,
        configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = Constants.SERVICE_DESCRIPTION, propertyPrivate = false,
                value = CasAuthenticationConstants.DEFAULT_SERVICE_DESCRIPTION_CAS_HTTP_SESSION_REGISTRY)
})
@Service
public class CasHttpSessionRegistryComponent implements
        CasHttpSessionRegistry,
        HttpSessionActivationListener,
        HttpSessionListener {

    private static final String SERVICE_TICKET_SESSION_ATTR_NAME = "org.everit.osgi.authentication.cas.ServiceTicket";

    private final Map<String, String> sessionIdsByServiceTickets = new ConcurrentHashMap<>();

    private final Map<String, HttpSession> sessionsBySessionId = new ConcurrentHashMap<>();

    @Override
    public void addSession(final String serviceTicket, final HttpSession httpSession) {
        httpSession.setAttribute(SERVICE_TICKET_SESSION_ATTR_NAME, serviceTicket);
        put(serviceTicket, httpSession);
    }

    private void put(final String nullableServiceTicket, final HttpSession httpSession) {
        String sessionId = httpSession.getId();
        sessionsBySessionId.put(sessionId, httpSession);

        Optional.ofNullable(nullableServiceTicket)
                .ifPresent((serviceTicket) -> sessionIdsByServiceTickets.put(serviceTicket, sessionId));
    }

    private void remove(final HttpSessionEvent httpSessionEvent) {
        HttpSession httpSession = httpSessionEvent.getSession();
        String sessionId = httpSession.getId();
        sessionsBySessionId.remove(sessionId);

        Optional.ofNullable(httpSession.getAttribute(SERVICE_TICKET_SESSION_ATTR_NAME))
                .ifPresent((serviceTicket) -> sessionIdsByServiceTickets.remove(serviceTicket));
    }

    @Override
    public Optional<HttpSession> removeByServiceTicket(final String serviceTicket) {
        String sessionId = sessionIdsByServiceTickets.remove(serviceTicket);
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessionsBySessionId.remove(sessionId));
    }

    @Override
    public void sessionCreated(final HttpSessionEvent httpSessionEvent) {
        // Nothing to do here
    }

    @Override
    public void sessionDestroyed(final HttpSessionEvent httpSessionEvent) {
        remove(httpSessionEvent);
    }

    @Override
    public void sessionDidActivate(final HttpSessionEvent httpSessionEvent) {
        HttpSession httpSession = httpSessionEvent.getSession();
        String serviceTicket = (String) httpSession.getAttribute(SERVICE_TICKET_SESSION_ATTR_NAME);
        put(serviceTicket, httpSession);
    }

    @Override
    public void sessionWillPassivate(final HttpSessionEvent httpSessionEvent) {
        remove(httpSessionEvent);
    }

}
