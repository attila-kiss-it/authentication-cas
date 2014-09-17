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
package org.everit.osgi.authentication.cas;

public final class CasAuthenticationConstants {

    public static final String SERVICE_FACTORYPID_CAS_AUTHENTICATION_FILTER =
            "org.everit.osgi.authentication.cas.CasAuthenticationFilter";

    public static final String DEFAULT_SERVICE_DESCRIPTION_CAS_AUTHENTICATION_FILTER =
            "Default CAS Authentication Filter";

    public static final String SERVICE_FACTORYPID_CAS_HTTP_SESSION_REGISTRY =
            "org.everit.osgi.authentication.cas.CasHttpSessionRegistry";

    public static final String DEFAULT_SERVICE_DESCRIPTION_CAS_HTTP_SESSION_REGISTRY =
            "Default CAS HttpSession Registry";

    public static final String PROP_CAS_SERVICE_TICKET_VALIDATION_URL = "cas.service.ticket.validation.url";

    public static final String DEFAULT_CAS_SERVICE_TICKET_VALIDATION_URL = "https://localhost:8443/cas/serviceValidate";

    public static final String PROP_FAILURE_URL = "failure.url";

    public static final String DEFAULT_FAILURE_URL = "/failed.html";

    public static final String PROP_REQ_PARAM_NAME_SERVICE_TICKET = "req.param.name.service.ticket";

    public static final String DEFAULT_REQ_PARAM_NAME_SERVICE_TICKET = "ticket";

    public static final String PROP_REQ_PARAM_NAME_LOGOUT_REQUEST = "req.param.name.logout.request";

    public static final String DEFAULT_REQ_PARAM_NAME_LOGOUT_REQUEST = "logoutRequest";

    public static final String PROP_AUTHENTICATION_SESSION_ATTRIBUTE_NAMES = "authenticationSessionAttributeNames.target";

    public static final String PROP_RESOURCE_ID_RESOLVER = "resourceIdResolver.target";

    public static final String PROP_CAS_HTTP_SESSION_REGISTRY = "casHttpSessionRegistry.target";

    public static final String PROP_LOG_SERVICE = "logService.target";

    private CasAuthenticationConstants() {
    }

}
