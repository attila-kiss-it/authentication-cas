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
 * A registry of {@link HttpSession}s used for CAS authentication. The instance of this registry is stored in the
 * {@link ServletContext} identified by a unique Service PID. A session is stored in the registry when a service ticket
 * is validated and a session is removed when a service ticket is invalidated.
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
 * <b>Persistent sessions</b>
 * </p>
 * <p>
 * If a node is restarted and a persistent session manager is used, then the registry can be rebuilt by invoking
 * {@link #putSession(HttpSession)} and {@link #removeBySession(HttpSession)} methods.
 * </p>
 */
public final class CasHttpSessionRegistry {

    /**
     * Creates the servlet context attribute name of the {@link CasHttpSessionRegistry} instance stored in the
     * {@link ServletContext}.
     *
     * @param servicePid
     *            the Service PID of the OSGi service that handles the CAS authentication. Used in the servlet context
     *            attribute name to guarantee its uniqueness.
     * @return the created servlet context attribute name
     */
    private static String createServletContextAttrNameInstance(final String servicePid) {
        return SERVLET_CONTEXT_ATTR_NAME_INSTANCE_PREFIX + servicePid;
    }

    /**
     * Returns an instance stored in {@link ServletContext} with the attribute name constructed from the Service PID.
     *
     * @param servicePid
     *            the Service PID of the OSGi service that handles the CAS authentication. Used to construct the
     *            {@link ServletContext} attribute name of the {@link CasHttpSessionRegistry}.
     * @param servletContext
     *            the {@link ServletContext} that stores the instance
     * @return the <code>non-null</code> {@link CasHttpSessionRegistry}
     * @throws IllegalStateException
     *             if the instance is not available
     */
    public static CasHttpSessionRegistry getInstance(final String servicePid, final ServletContext servletContext) {
        Optional<CasHttpSessionRegistry> optionalInstance =
                CasHttpSessionRegistry.getOptionalInstance(servicePid, servletContext);
        return optionalInstance.orElseThrow(() -> {
            String servletContextAttrName = CasHttpSessionRegistry.createServletContextAttrNameInstance(servicePid);
            return new IllegalStateException("[" + servletContextAttrName + "] "
                    + "ServletContext attribute not availbale. "
                    + "Possible cause: ServletContext is not initialized by "
                    + "CasAuthenticationFilterComponent yet (the sessions was restored before "
                    + "ServletContext initialization).");
        });
    }

    private static Optional<CasHttpSessionRegistry> getOptionalInstance(final String servicePid,
            final ServletContext servletContext) {
        String servletContextAttrName = CasHttpSessionRegistry.createServletContextAttrNameInstance(servicePid);
        return Optional.ofNullable((CasHttpSessionRegistry) servletContext.getAttribute(servletContextAttrName));
    }

    /**
     * Registers a new instance to the {@link ServletContext} with the attribute name constructed from the Service PID.
     *
     * @param servicePid
     *            the Service PID of the OSGi service that handles the CAS authentication. Used to construct the
     *            {@link ServletContext} attribute name of the {@link CasHttpSessionRegistry}.
     * @param servletContext
     *            the {@link ServletContext} where the new instance will be registered
     * @throws IllegalStateException
     *             if an instance is already registered with the Service PID
     */
    public static void registerInstance(final String servicePid, final ServletContext servletContext) {
        String servletContextAttrName = CasHttpSessionRegistry.createServletContextAttrNameInstance(servicePid);
        Optional<CasHttpSessionRegistry> optionalInstance =
                CasHttpSessionRegistry.getOptionalInstance(servicePid, servletContext);
        optionalInstance.ifPresent((instance) -> {
            throw new IllegalStateException("ServletContext attribute [" + servletContextAttrName + "] "
                    + "already registered. Possible cause: the EventListeners implemented by "
                    + "CasAuthenticationFilterComponent is registered multiple times to the "
                    + "ServletContextHandler.");
        });
        servletContext.setAttribute(servletContextAttrName, new CasHttpSessionRegistry());
    }

    /**
     * Removes the instance from the {@link ServletContext} if available.
     *
     * @param servicePid
     *            the Service PID of the OSGi service that handles the CAS authentication. Used to construct the
     *            {@link ServletContext} attribute name of the {@link CasHttpSessionRegistry}.
     * @param servletContext
     *            the instance will be removed from this servlet context
     */
    public static void removeInstance(final String servicePid, final ServletContext servletContext) {
        String servletContextAttrName = CasHttpSessionRegistry.createServletContextAttrNameInstance(servicePid);
        servletContext.removeAttribute(servletContextAttrName);
    }

    /**
     * The servlet context attribute name prefix used for the {@link CasHttpSessionRegistry} instance.
     */
    private static final String SERVLET_CONTEXT_ATTR_NAME_INSTANCE_PREFIX =
            CasHttpSessionRegistry.class.getName() + ".";

    /**
     * The session attribute name used for the service ticket.
     */
    private static final String SESSION_ATTR_NAME_SERVICE_TICKET =
            "org.everit.osgi.authentication.cas.ServiceTicket";

    /**
     * The cache of the sessionIds mapped by the CAS service tickets. Key: CAS service ticket, Value: HTTP Session id.
     * In case of CAS logout the CAS server invalidates the service ticket and sends it in a logout request
     * asynchronously. With this map it is possible to retrieve the session ID belonging to a service ticket.
     */
    private final Map<String, String> sessionIdsByServiceTickets = new ConcurrentHashMap<>();

    /**
     * The cache of the {@link HttpSession}s mapped by the session IDs. Key: session ID, Value: {@link HttpSession}. In
     * case of CAS logout the CAS server invalidates the service ticket and sends it in a logout request asynchronously.
     * Using the {@link #sessionIdsByServiceTickets} map it is possible to retrieve the Session ID belonging to a
     * service ticket and with this map it is possible to retrieve the HttpSession by that Session ID.
     */
    private final Map<String, HttpSession> sessionsBySessionId = new ConcurrentHashMap<>();

    /**
     * Private constructor. Use {@link #registerInstance(String, ServletContext)} to instantiate and register this
     * {@link CasHttpSessionRegistry} to the servlet context.
     */
    private CasHttpSessionRegistry() {
    }

    /**
     * Adds the session to the registry identified by the CAS service ticket. Must be invoked when the CAS service
     * ticket is validated successfully on the CAS server.
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

        httpSession.setAttribute(SESSION_ATTR_NAME_SERVICE_TICKET, serviceTicket);
        String sessionId = httpSession.getId();
        sessionsBySessionId.put(sessionId, httpSession);
        sessionIdsByServiceTickets.put(serviceTicket, sessionId);
    }

    /**
     * Adds the session that already contains a CAS service ticket to the registry. Must be invoked when a persistent
     * session is restored and has just been activated.
     *
     * @param httpSession
     *            the restored {@link HttpSession}
     * @throws NullPointerException
     *             if the <code>httpSession</code> argument is <code>null</code> or it does not contain a CAS service
     *             ticket with attribute name {@value #SESSION_ATTR_NAME_SERVICE_TICKET}
     */
    public void putSession(final HttpSession httpSession) {
        Objects.requireNonNull(httpSession, "httpSession cannot be null");
        String serviceTicket = (String) httpSession.getAttribute(SESSION_ATTR_NAME_SERVICE_TICKET);
        put(serviceTicket, httpSession);
    }

    /**
     * Removes the session from the registry if available. Must be invoked when a CAS server invalidates a service
     * ticket. Using this method the caches will be cleaned and the returned {@link HttpSession} can be invalidated.
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

    /**
     * Removes the session from the registry if available. Must be invoked when a session is destroyed or a persistent
     * session will be persisted and is about to be passivated.
     *
     * @param httpSession
     *            the {@link HttpSession} to remove that optionally contains a CAS service ticket with attribute name
     *            {@value #SESSION_ATTR_NAME_SERVICE_TICKET}
     */
    public void removeBySession(final HttpSession httpSession) {
        Objects.requireNonNull(httpSession, "httpSession cannot be null");
        String sessionId = httpSession.getId();

        sessionsBySessionId.remove(sessionId);

        Optional.ofNullable(httpSession.getAttribute(SESSION_ATTR_NAME_SERVICE_TICKET))
                .ifPresent((serviceTicket) -> sessionIdsByServiceTickets.remove(serviceTicket));
    }

}
