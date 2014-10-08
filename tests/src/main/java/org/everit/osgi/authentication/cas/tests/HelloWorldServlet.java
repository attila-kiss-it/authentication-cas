/**
 * This file is part of Everit - CAS authentication tests.
 *
 * Everit - CAS authentication tests is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - CAS authentication tests is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - CAS authentication tests.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.authentication.cas.tests;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.everit.osgi.authentication.context.AuthenticationContext;

public class HelloWorldServlet extends HttpServlet {

    private static final long serialVersionUID = -3769761010329362073L;

    public static final String GUEST = "guest";

    public static final String UNKNOWN = "unknown";

    private final AuthenticationContext authenticationContext;

    public HelloWorldServlet(final AuthenticationContext authenticationContext) {
        super();
        this.authenticationContext = authenticationContext;
    }

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
            IOException {
        long currentResourceId = authenticationContext.getCurrentResourceId();
        String userName = getUserName(currentResourceId);

        resp.setContentType("text/plain");
        PrintWriter out = resp.getWriter();
        out.print(userName);
        out.print("@");
        out.print(req.getServerName());
    }

    private String getUserName(final long currentResourceId) {
        if (currentResourceId == authenticationContext.getDefaultResourceId()) {
            return GUEST;
        } else if (currentResourceId == CasResourceIdResolver.JOHNDOE_RESOURCE_ID.get().longValue()) {
            return CasResourceIdResolver.JOHNDOE;
        } else if (currentResourceId == CasResourceIdResolver.JANEDOE_RESOURCE_ID.get().longValue()) {
            return CasResourceIdResolver.JANEDOE;
        } else {
            return UNKNOWN;
        }
    }

}
