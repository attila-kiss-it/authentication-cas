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

    public static final String SERVICE_FACTORYPID_CAS_AUTHENTICATION =
            "org.everit.osgi.authentication.cas.CasAuthentication";

    public static final String DEFAULT_SERVICE_DESCRIPTION_CAS_AUTHENTICATION =
            "Default CAS Authentication";

    public static final String PROP_CAS_SERVICE_TICKET_VALIDATION_URL = "cas.service.ticket.validation.url";

    public static final String DEFAULT_CAS_SERVICE_TICKET_VALIDATION_URL = "https://localhost:8443/cas/serviceValidate";

    public static final String PROP_FAILURE_URL = "failure.url";

    public static final String DEFAULT_FAILURE_URL = "/failed.html";

    public static final String PROP_AUTHENTICATION_SESSION_ATTRIBUTE_NAMES = "authenticationSessionAttributeNames.target";

    public static final String PROP_RESOURCE_ID_RESOLVER = "resourceIdResolver.target";

    public static final String PROP_SAX_PARSER_FACTORY = "saxParserFactory.target";

    public static final String PROP_LOG_SERVICE = "logService.target";

    private CasAuthenticationConstants() {
    }

}
