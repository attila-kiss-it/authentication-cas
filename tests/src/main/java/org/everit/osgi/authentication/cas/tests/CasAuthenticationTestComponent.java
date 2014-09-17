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

import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.Servlet;
import javax.servlet.http.HttpSessionActivationListener;
import javax.servlet.http.HttpSessionListener;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.junit.Test;
import org.osgi.framework.BundleContext;

@Component(name = "CasAuthenticationTest", metatype = true, configurationFactory = true,
        policy = ConfigurationPolicy.REQUIRE, immediate = true)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "CasAuthenticationTest"),
        @Property(name = "helloWorldServlet.target"),
        @Property(name = "sessionAuthenticationFilter.target"),
        @Property(name = "sessionLogoutServlet.target"),
        @Property(name = "casAuthenticationFilter.target"),
        @Property(name = "casHttpSessionActivationListener.target"),
        @Property(name = "casHttpSessionListener.target")
})
@Service(value = CasAuthenticationTestComponent.class)
public class CasAuthenticationTestComponent {

    private static final String HELLO_SERVLET_ALIAS = "/hello";

    private static final String LOGOUT_SERVLET_ALIAS = "/logout";

    @Reference(bind = "setHelloWorldServlet")
    private Servlet helloWorldServlet;

    @Reference(bind = "setSessionAuthenticationFilter")
    private Filter sessionAuthenticationFilter;

    @Reference(bind = "setSessionLogoutServlet")
    private Servlet sessionLogoutServlet;

    @Reference(bind = "setCasAuthenticationFilter")
    private Filter casAuthenticationFilter;

    @Reference(bind = "setCasHttpSessionActivationListener")
    private HttpSessionActivationListener casHttpSessionActivationListener;

    @Reference(bind = "setCasHttpSessionListener")
    private HttpSessionListener casHttpSessionListener;

    private String helloUrl;

    private Server testServer;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties)
            throws Exception {
        testServer = new Server(8081);
        ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        SessionHandler sessionHandler = servletContextHandler.getSessionHandler();
        sessionHandler.addEventListener(casHttpSessionListener);
        sessionHandler.addEventListener(casHttpSessionActivationListener);

        testServer.setHandler(servletContextHandler);

        servletContextHandler.addFilter(
                new FilterHolder(sessionAuthenticationFilter), "/*", null);
        servletContextHandler.addFilter(
                new FilterHolder(casAuthenticationFilter), "/*", null);
        servletContextHandler.addServlet(
                new ServletHolder("helloWorldServlet", helloWorldServlet), HELLO_SERVLET_ALIAS);
        servletContextHandler.addServlet(
                new ServletHolder("sessionLogoutServlet", sessionLogoutServlet), LOGOUT_SERVLET_ALIAS);

        testServer.start();

        String testServerURI = testServer.getURI().toString();
        String testServerURL = testServerURI.substring(0, testServerURI.length() - 1);

        // helloUrl = testServerURL + HELLO_SERVLET_ALIAS;
    }

    @Deactivate
    public void deactivate() throws Exception {
        if (testServer != null) {
            testServer.stop();
            testServer.destroy();
        }
    }

    public void setCasAuthenticationFilter(final Filter casAuthenticationFilter) {
        this.casAuthenticationFilter = casAuthenticationFilter;
    }

    public void setCasHttpSessionActivationListener(final HttpSessionActivationListener casHttpSessionActivationListener) {
        this.casHttpSessionActivationListener = casHttpSessionActivationListener;
    }

    public void setCasHttpSessionListener(final HttpSessionListener casHttpSessionListener) {
        this.casHttpSessionListener = casHttpSessionListener;
    }

    // private long hello(final HttpContext httpContext, final long expectedResourceId) throws IOException {
    // HttpClient httpClient = new DefaultHttpClient();
    // HttpGet httpGet = new HttpGet(helloUrl);
    // HttpResponse httpResponse = httpClient.execute(httpGet, httpContext);
    // Assert.assertEquals(HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
    // HttpEntity responseEntity = httpResponse.getEntity();
    // InputStream inputStream = responseEntity.getContent();
    // StringWriter writer = new StringWriter();
    // IOUtils.copy(inputStream, writer);
    // String[] responseBodyAsString = writer.toString().split(":");
    // long actualResourceId = Long.valueOf(responseBodyAsString[0]).longValue();
    // long newResourceId = Long.valueOf(responseBodyAsString[1]).longValue();
    // String st = responseBodyAsString.length == 3 ? responseBodyAsString[2] : "should be success";
    // Assert.assertEquals(st.replaceAll("-->", ":"), expectedResourceId, actualResourceId);
    // return newResourceId;
    // }

    // private void logoutGet(final HttpContext httpContext) throws ClientProtocolException, IOException {
    // HttpClient httpClient = new DefaultHttpClient();
    // HttpGet httpGet = new HttpGet(logoutUrl);
    // HttpResponse httpResponse = httpClient.execute(httpGet, httpContext);
    // Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, httpResponse.getStatusLine().getStatusCode());
    //
    // HttpUriRequest currentReq = (HttpUriRequest) httpContext.getAttribute(ExecutionContext.HTTP_REQUEST);
    // HttpHost currentHost = (HttpHost) httpContext.getAttribute(ExecutionContext.HTTP_TARGET_HOST);
    // String currentUrl = (currentReq.getURI().isAbsolute())
    // ? currentReq.getURI().toString()
    // : (currentHost.toURI() + currentReq.getURI());
    // Assert.assertEquals(successLogoutUrl, currentUrl);
    // }

    // private void logoutPost(final HttpContext httpContext) throws ClientProtocolException, IOException {
    // HttpClient httpClient = new DefaultHttpClient();
    // HttpPost httpPost = new HttpPost(logoutUrl);
    // HttpResponse httpResponse = httpClient.execute(httpPost, httpContext);
    // Assert.assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, httpResponse.getStatusLine().getStatusCode());
    // Header locationHeader = httpResponse.getFirstHeader("Location");
    // Assert.assertEquals(successLogoutUrl, locationHeader.getValue());
    // }

    public void setHelloWorldServlet(final Servlet helloWorldServlet) {
        this.helloWorldServlet = helloWorldServlet;
    }

    public void setSessionAuthenticationFilter(final Filter sessionAuthenticationFilter) {
        this.sessionAuthenticationFilter = sessionAuthenticationFilter;
    }

    public void setSessionLogoutServlet(final Servlet sessionLogoutServlet) {
        this.sessionLogoutServlet = sessionLogoutServlet;
    }

    @Test
    public void testAccessHelloPage() throws Exception {
        // CookieStore cookieStore = new BasicCookieStore();
        // HttpContext httpContext = new BasicHttpContext();
        // httpContext.setAttribute(ClientContext.COOKIE_STORE, cookieStore);
        //
        // long sessionResourceId = hello(httpContext, authenticationContext.getDefaultResourceId());
        // sessionResourceId = hello(httpContext, sessionResourceId);
        // sessionResourceId = hello(httpContext, sessionResourceId);
        // logoutPost(httpContext);
        //
        // sessionResourceId = hello(httpContext, authenticationContext.getDefaultResourceId());
        // sessionResourceId = hello(httpContext, sessionResourceId);
        // sessionResourceId = hello(httpContext, sessionResourceId);
        // logoutGet(httpContext);
        //
        // hello(httpContext, authenticationContext.getDefaultResourceId());
    }

}
