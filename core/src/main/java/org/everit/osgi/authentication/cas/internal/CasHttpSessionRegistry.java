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
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;

/**
 * A {@link HttpSession} registry used for CAS authentication. The session is stored when a service ticket is validated
 * and a session is removed when a service ticket is invalidated.
 * <p>
 * <b>Distributed environments</b>
 * </p>
 * <p>
 * In distributed environments every node has its own instance of {@link CasHttpSessionRegistry}. In case of CAS logout
 * (service ticket invalidation) the registry must be cleaned in every case to prevent memory leaks. This can be
 * achieved by forwarding the CAS logout request to every node by a <i>load balancer</i>. The logout request will be
 * processed by the {@link org.everit.osgi.authentication.cas.internal.CasAuthenticationFilterComponent} configured on
 * the nodes. This filter will remove the session from the registry and invalidates it.
 * </p>
 * <p>
 * <b>Sticky sessions</b>
 * </p>
 * <p>
 * If a node is restarted and persistent session manager is used, then the registry WILL NOT be rebuilt. In that case if
 * a CAS logout request is received after the restart, no session invalidation can be done by the filter (because there
 * are no sessions in the registry). Therefore the users "assigned" to that node are still logged in.
 * </p>
 * <p>
 * <b>Implementation</b>
 * </p>
 * <p>
 * The implementation MUST take care of the lifecycle of the {@link HttpSession}. It is recommended to implement the
 * {@link javax.servlet.http.HttpSessionListener} interface as well to clear the registry if a session is destroyed.
 * </p>
 */
public final class CasHttpSessionRegistry {

    public static CasHttpSessionRegistry getInstance(final String servicePid, final ServletContext servletContext) {
        return CasHttpSessionRegistry.getOptionalInstance(servicePid, servletContext)
                .orElseThrow(() -> {
                    String servletContextAttrName =
                            CasHttpSessionRegistry.getServletContextAttrName(servicePid);
                    return new IllegalStateException("[" + servletContextAttrName + "]"
                            + " ServletContext attribute not availbale");
                });
    }

    private static Optional<CasHttpSessionRegistry> getOptionalInstance(final String servicePid,
            final ServletContext servletContext) {
        String servletContextAttrName = CasHttpSessionRegistry.getServletContextAttrName(servicePid);
        return Optional.ofNullable((CasHttpSessionRegistry) servletContext.getAttribute(servletContextAttrName));
    }

    private static String getServletContextAttrName(final String servicePid) {
        return CasHttpSessionRegistry.class.getName() + "." + servicePid;
    }

    public static void registerInstance(final String servicePid, final ServletContext servletContext) {
        String servletContextAttrName = CasHttpSessionRegistry.getServletContextAttrName(servicePid);
        CasHttpSessionRegistry.getOptionalInstance(servicePid, servletContext)
                .ifPresent((instance) -> {
                    throw new IllegalStateException("ServletContext attribute [" + servletContextAttrName + "]"
                            + " already registered");
                });
        servletContext.setAttribute(servletContextAttrName, new CasHttpSessionRegistry());
    }

    public static void removeInstance(final String servicePid, final ServletContext servletContext) {
        String servletContextAttrName = CasHttpSessionRegistry.getServletContextAttrName(servicePid);
        servletContext.removeAttribute(servletContextAttrName);
    }

    private static final String SERVICE_TICKET_SESSION_ATTR_NAME = "org.everit.osgi.authentication.cas.ServiceTicket";

    private final Map<String, String> sessionIdsByServiceTickets = new ConcurrentHashMap<>();

    private final Map<String, HttpSession> sessionsBySessionId = new ConcurrentHashMap<>();

    private CasHttpSessionRegistry() {
    }

    /**
     * Adds the session to the registry identified by the CAS service ticket. This method is invoked when the CAS
     * service ticket is validated successfully on the CAS server.
     *
     * @param serviceTicket
     *            the validated CAS service ticket
     * @param httpSession
     *            the {@link HttpSession} of the actual {@link javax.servlet.http.HttpServletRequest} initiated by the
     *            user
     * @throws NullPointerException
     *             if one of the arguments are <code>null</code>
     */
    public void put(final String serviceTicket, final HttpSession httpSession) {
        Objects.requireNonNull(serviceTicket, "serviceTicket cannot be null");
        Objects.requireNonNull(httpSession, "httpSession cannot be null");

        httpSession.setAttribute(SERVICE_TICKET_SESSION_ATTR_NAME, serviceTicket);
        String sessionId = httpSession.getId();
        sessionsBySessionId.put(sessionId, httpSession);
        sessionIdsByServiceTickets.put(serviceTicket, sessionId);
    }

    public void putSession(final HttpSession httpSession) {
        String serviceTicket = (String) httpSession.getAttribute(SERVICE_TICKET_SESSION_ATTR_NAME);
        put(serviceTicket, httpSession);
    }

    /**
     * Removes the session from the registry is available. Invoked when a CAS server invalidates a service ticket.
     *
     * @param serviceTicket
     *            the invalidated service ticket
     * @return the {@link HttpSession} if it is handled by this registry
     * @throws NullPointerException
     *             if the provided <code>serviceTicket</code> is <code>null</code>
     */
    public Optional<HttpSession> removeByServiceTicket(final String serviceTicket) {
        Objects.requireNonNull(serviceTicket, "serviceTicket cannot be null");
        String sessionId = sessionIdsByServiceTickets.remove(serviceTicket);
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessionsBySessionId.remove(sessionId));
    }

    public void removeBySession(final HttpSession httpSession) {
        Objects.requireNonNull(httpSession, "httpSession cannot be null");
        String sessionId = httpSession.getId();

        sessionsBySessionId.remove(sessionId);

        Optional.ofNullable(httpSession.getAttribute(SERVICE_TICKET_SESSION_ATTR_NAME))
                .ifPresent((serviceTicket) -> sessionIdsByServiceTickets.remove(serviceTicket));
    }

}
