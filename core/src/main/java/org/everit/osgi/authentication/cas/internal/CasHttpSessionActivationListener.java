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

import java.io.Serializable;
import java.util.Objects;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionActivationListener;
import javax.servlet.http.HttpSessionEvent;

public class CasHttpSessionActivationListener implements HttpSessionActivationListener, Serializable {

    public static String getInstanceSessionAttrName(final String servicePid) {
        return CasHttpSessionActivationListener.class.getName() + ".instance." + servicePid;
    }

    public static String getServicePidSessionAttrName(final String servicePid) {
        return SESSION_ATTR_NAME_SERVICE_PID_PREFIX + servicePid;
    }

    public static void registerInstance(final String servicePid, final HttpSession httpSession) {
        String sessionAttrName = CasHttpSessionActivationListener.getInstanceSessionAttrName(servicePid);
        httpSession.setAttribute(sessionAttrName, new CasHttpSessionActivationListener(servicePid));
    }

    public static void removeInstance(final String servicePid, final HttpSession httpSession) {
        String sessionAttrName = CasHttpSessionActivationListener.getInstanceSessionAttrName(servicePid);
        httpSession.removeAttribute(sessionAttrName);
    }

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 7270104873395140181L;

    public static final String SESSION_ATTR_NAME_SERVICE_PID_PREFIX =
            CasHttpSessionActivationListener.class.getName() + ".servicePid.";

    private final String servicePid;

    private CasHttpSessionActivationListener(final String servicePid) {
        super();
        this.servicePid = Objects.requireNonNull(servicePid, "servicePid cannot be null");
    }

    @Override
    public void sessionDidActivate(final HttpSessionEvent httpSessionEvent) {
        HttpSession httpSession = httpSessionEvent.getSession();
        ServletContext servletContext = httpSession.getServletContext();
        CasHttpSessionRegistry.getInstance(servicePid, servletContext).putSession(httpSession);
    }

    @Override
    public void sessionWillPassivate(final HttpSessionEvent httpSessionEvent) {
        HttpSession httpSession = httpSessionEvent.getSession();
        ServletContext servletContext = httpSession.getServletContext();
        CasHttpSessionRegistry.getInstance(servicePid, servletContext).removeBySession(httpSession);
        // prepare to session serialization
        httpSession.setAttribute(
                CasHttpSessionActivationListener.getServicePidSessionAttrName(servicePid),
                servicePid);
    }

}
