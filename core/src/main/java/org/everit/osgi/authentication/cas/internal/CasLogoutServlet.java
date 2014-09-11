package org.everit.osgi.authentication.cas.internal;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CasLogoutServlet extends HttpServlet {

    private static final long serialVersionUID = 5904484742173432400L;

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
            IOException {
        logout(req, resp);
    }

    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
            IOException {
        logout(req, resp);
    }

    private void logout(final HttpServletRequest req, final HttpServletResponse resp) {
        // TODO Auto-generated method stub

    }

}
