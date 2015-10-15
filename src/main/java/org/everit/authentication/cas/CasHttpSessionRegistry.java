/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.biz)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.everit.authentication.cas;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpSession;

/**
 * A registry of {@link HttpSession}s used for CAS authentication. A session is stored in the
 * registry when a service ticket is validated and a session is removed when a service ticket is
 * invalidated.
 * <p>
 * <b>Distributed environments</b>
 * </p>
 * <p>
 * In distributed environments every node has its own instance of {@link CasHttpSessionRegistry}. In
 * case of CAS logout (service ticket invalidation) the registry must be cleaned in every case to
 * prevent memory leaks. This can be achieved by forwarding the CAS logout request to every node by
 * a <i>load balancer</i>. The logout request will be processed by the
 * {@link org.everit.authentication.cas.CasAuthentication} configured on the nodes. This filter will
 * remove the session from the registry and invalidates it.
 * </p>
 * <p>
 * <b>Persistent sessions</b>
 * </p>
 * <p>
 * If a node is restarted and a persistent session manager is used, then the registry can be rebuilt
 * by invoking {@link #putSession(HttpSession)} and {@link #removeBySession(HttpSession)} methods.
 * </p>
 */
public final class CasHttpSessionRegistry {

  /**
   * The session attribute name used for the service ticket.
   */
  public static final String SESSION_ATTR_NAME_SERVICE_TICKET =
      "org.everit.authentication.cas.ServiceTicket";

  /**
   * The cache of the sessionIds mapped by the CAS service tickets. Key: CAS service ticket, Value:
   * HTTP Session id. In case of CAS logout the CAS server invalidates the service ticket and sends
   * it in a logout request asynchronously. With this map it is possible to retrieve the session ID
   * belonging to a service ticket.
   */
  private final Map<String, String> sessionIdsByServiceTickets = new ConcurrentHashMap<>();

  /**
   * The cache of the {@link HttpSession}s mapped by the session IDs. Key: session ID, Value:
   * {@link HttpSession}. In case of CAS logout the CAS server invalidates the service ticket and
   * sends it in a logout request asynchronously. Using the {@link #sessionIdsByServiceTickets} map
   * it is possible to retrieve the Session ID belonging to a service ticket and with this map it is
   * possible to retrieve the HttpSession by that Session ID.
   */
  private final Map<String, HttpSession> sessionsBySessionId = new ConcurrentHashMap<>();

  /**
   * Adds the session to the registry identified by the CAS service ticket. Must be invoked when the
   * CAS service ticket is validated successfully on the CAS server.
   *
   * @param httpSession
   *          the {@link HttpSession} of the actual {@link javax.servlet.http.HttpServletRequest}
   *          initiated by the user
   * @param serviceTicket
   *          the validated CAS service ticket
   *
   * @throws NullPointerException
   *           if one of the arguments are <code>null</code>
   */
  public void put(final HttpSession httpSession, final String serviceTicket) {
    Objects.requireNonNull(serviceTicket, "serviceTicket cannot be null");
    Objects.requireNonNull(httpSession, "httpSession cannot be null");

    httpSession.setAttribute(SESSION_ATTR_NAME_SERVICE_TICKET, serviceTicket);
    String sessionId = httpSession.getId();
    sessionsBySessionId.put(sessionId, httpSession);
    sessionIdsByServiceTickets.put(serviceTicket, sessionId);
  }

  /**
   * Adds the session to the registry that already contains a CAS service ticket to the registry.
   * Must be invoked when a persistent session is restored and has just been activated.
   *
   * @param httpSession
   *          the restored {@link HttpSession}
   */
  public void putSession(final HttpSession httpSession) {
    String serviceTicket = (String) httpSession.getAttribute(SESSION_ATTR_NAME_SERVICE_TICKET);
    if (serviceTicket == null) {
      return;
    }
    put(httpSession, serviceTicket);
  }

  /**
   * Removes the session from the registry if available. Must be invoked when a CAS server
   * invalidates a service ticket. Using this method the caches will be cleaned and the returned
   * {@link HttpSession} can be invalidated.
   *
   * @param serviceTicket
   *          the invalidated service ticket
   * @return the {@link HttpSession} if it is handled by this registry
   * @throws NullPointerException
   *           if the provided <code>serviceTicket</code> is <code>null</code>
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
   * Removes the session from the registry if available. Must be invoked when a session is destroyed
   * or a persistent session will be persisted and is about to be passivated.
   *
   * @param httpSession
   *          the {@link HttpSession} to remove that optionally contains a CAS service ticket with
   *          attribute name {@value #SESSION_ATTR_NAME_SERVICE_TICKET}
   */
  public void removeBySession(final HttpSession httpSession) {
    Objects.requireNonNull(httpSession, "httpSession cannot be null");
    String sessionId = httpSession.getId();

    sessionsBySessionId.remove(sessionId);

    Optional.ofNullable(httpSession.getAttribute(SESSION_ATTR_NAME_SERVICE_TICKET))
        .ifPresent((serviceTicket) -> sessionIdsByServiceTickets.remove(serviceTicket));
  }

}
