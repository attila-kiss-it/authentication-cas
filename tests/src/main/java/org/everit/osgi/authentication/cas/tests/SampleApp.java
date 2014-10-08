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

import java.io.File;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EventListener;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.server.AbstractNetworkConnector;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.session.HashSessionManager;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.everit.osgi.authentication.context.AuthenticationContext;
import org.junit.Assert;
import org.osgi.framework.BundleContext;

public class SampleApp {

    public static void pingCasLoginUrl(final BundleContext bundleContext) throws Exception {
        CloseableHttpClient httpClient = new SecureHttpClient(null, bundleContext).getHttpClient();

        HttpGet httpGet = new HttpGet(CAS_LOGIN_URL + "?" + LOCALE);
        HttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpGet);
            Assert.assertEquals(CAS_PING_FAILURE_MESSAGE,
                    HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(CAS_PING_FAILURE_MESSAGE);
        } finally {
            if (httpResponse != null) {
                EntityUtils.consume(httpResponse.getEntity());
            }
            httpClient.close();
        }
    }

    private static final String HELLO_SERVLET_ALIAS = "/hello";

    private static final String LOGOUT_SERVLET_ALIAS = "/logout";

    private static final String LOCALE = "locale=en";

    private static final String CAS_URL = "https://localhost:8443/cas";

    private static final String CAS_LOGOUT_URL = CAS_URL + "/logout";

    private static final String CAS_LOGIN_URL = CAS_URL + "/login";

    private static final String CAS_PING_FAILURE_MESSAGE = "CAS login URL [" + CAS_LOGIN_URL + "] not available! "
            + "Jetty should be executed by jetty-maven-plugin automatically in pre-integration-test phase "
            + "or manually using the 'mvn jetty:run' command (see pom.xml).";

    private static final String CAS_LT_BEGIN = "name=\"lt\" value=\"";

    private static final String CAS_EXECUTION_BEGIN = "name=\"execution\" value=\"";

    private final Server server;

    private final int port;

    private final String helloServiceUrl;

    private final String sessionLogoutUrl;

    private final String loggedOutUrl;

    private final String failedUrl;

    private final String hostname;

    public SampleApp(
            final String hostname,
            final Filter sessionAuthenticationFilter,
            final Servlet sessionLogoutServlet,
            final Filter casAuthenticationFilter,
            final EventListener casAuthenticationEventListener,
            final AuthenticationContext authenticationContext) throws Exception {
        super();
        this.hostname = hostname;
        server = new Server(0);

        // Initialize servlet context
        ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        servletContextHandler.setVirtualHosts(new String[] { hostname });

        servletContextHandler.addFilter(
                new FilterHolder(sessionAuthenticationFilter), "/*", null);
        servletContextHandler.addFilter(
                new FilterHolder(casAuthenticationFilter), "/*", null);
        servletContextHandler.addServlet(
                new ServletHolder("helloWorldServlet", new HelloWorldServlet(authenticationContext)),
                HELLO_SERVLET_ALIAS);
        servletContextHandler.addServlet(
                new ServletHolder("sessionLogoutServlet", sessionLogoutServlet), LOGOUT_SERVLET_ALIAS);

        servletContextHandler.addEventListener(casAuthenticationEventListener);
        server.setHandler(servletContextHandler);

        // Initialize session management
        HashSessionManager sessionManager = new HashSessionManager();
        String sessionStoreDirecotry = System.getProperty("jetty.session.store.directory");
        sessionManager.setStoreDirectory(new File(sessionStoreDirecotry));
        sessionManager.setLazyLoad(true); // required to initialize the servlet context before restoring the sessions
        sessionManager.addEventListener(casAuthenticationEventListener);

        SessionHandler sessionHandler = servletContextHandler.getSessionHandler();
        sessionHandler.setSessionManager(sessionManager);

        start();

        URI serverUri = server.getURI();
        port = serverUri.getPort();

        String testServerURI = serverUri.toString();
        String testServerURL = testServerURI.substring(0, testServerURI.length() - 1);

        helloServiceUrl = testServerURL + HELLO_SERVLET_ALIAS;
        sessionLogoutUrl = testServerURL + "/logout";
        loggedOutUrl = testServerURL + "/logged-out.html";
        failedUrl = testServerURL + "/failed.html";
    }

    public void assertHello(final SecureHttpClient secureHttpClient, final String expectedPrincipal) throws Exception {

        CloseableHttpClient httpClient = secureHttpClient.getHttpClient();
        HttpClientContext httpClientContext = secureHttpClient.getHttpClientContext();

        HttpGet httpGet = new HttpGet(helloServiceUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals("Failed to access URL [" + helloServiceUrl + "]", HttpServletResponse.SC_OK, httpResponse
                .getStatusLine().getStatusCode());
        HttpEntity responseEntity = httpResponse.getEntity();
        InputStream inputStream = responseEntity.getContent();
        StringWriter writer = new StringWriter();
        IOUtils.copy(inputStream, writer);
        String responseBodyAsString = writer.toString();
        Assert.assertEquals(expectedPrincipal + "@" + hostname, responseBodyAsString);
        EntityUtils.consume(responseEntity);
    }

    public void casLogin(final SecureHttpClient secureHttpClient) throws Exception {
        casLogin(secureHttpClient, false);
    }

    private void casLogin(final SecureHttpClient secureHttpClient, final boolean manipulateTicket) throws Exception {

        CloseableHttpClient httpClient = secureHttpClient.getHttpClient();
        HttpClientContext httpClientContext = secureHttpClient.getHttpClientContext();

        String casLoginUrl = CAS_LOGIN_URL + "?" + LOCALE + "&service="
                + URLEncoder.encode(helloServiceUrl, StandardCharsets.UTF_8.displayName());
        String[] hiddenFormParams = getHiddenParamsFromCasLoginForm(httpClient, httpClientContext, casLoginUrl);

        // CAS login
        HttpPost httpPost = new HttpPost(casLoginUrl);
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("username", secureHttpClient.getPrincipal()));
        parameters.add(new BasicNameValuePair("password", secureHttpClient.getPrincipal()));
        parameters.add(new BasicNameValuePair("lt", hiddenFormParams[0]));
        parameters.add(new BasicNameValuePair("execution", hiddenFormParams[1]));
        parameters.add(new BasicNameValuePair("_eventId", "submit"));
        parameters.add(new BasicNameValuePair("submit", "LOGIN"));
        HttpEntity httpEntity = new UrlEncodedFormEntity(parameters);
        httpPost.setEntity(httpEntity);

        HttpResponse httpResponse = httpClient.execute(httpPost, httpClientContext);
        Assert.assertEquals("No redirect after URL [" + casLoginUrl + "]",
                HttpServletResponse.SC_MOVED_TEMPORARILY, httpResponse.getStatusLine().getStatusCode());
        Header locationHeader = httpResponse.getFirstHeader("Location");
        Assert.assertNotNull(locationHeader);
        String ticketValidationUrl = locationHeader.getValue();
        Assert.assertTrue(ticketValidationUrl.startsWith(helloServiceUrl));
        String locale = getLocale(httpClientContext);
        Assert.assertNotNull(locale);
        EntityUtils.consume(httpResponse.getEntity());

        // CAS ticket validation
        ticketValidationUrl = ticketValidationUrl + "&locale=" + locale;

        if (manipulateTicket) {
            ticketValidationUrl = ticketValidationUrl.replace("ticket=", "ticket=X");
        }

        HttpGet httpGet = new HttpGet(ticketValidationUrl);
        httpResponse = httpClient.execute(httpGet, httpClientContext);

        if (!manipulateTicket &&
                (secureHttpClient.getPrincipal().equals(CasResourceIdResolver.JOHNDOE)
                || secureHttpClient.getPrincipal().equals(CasResourceIdResolver.JANEDOE))) {
            Assert.assertEquals("Failed to access URL [" + ticketValidationUrl + "]",
                    HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());

            HttpUriRequest currentReq = (HttpUriRequest) httpClientContext.getRequest();
            HttpHost currentHost = httpClientContext.getTargetHost();
            String currentUrl = (currentReq.getURI().isAbsolute())
                    ? currentReq.getURI().toString()
                    : (currentHost.toURI() + currentReq.getURI());
            Assert.assertEquals(helloServiceUrl, currentUrl);
            httpEntity = httpResponse.getEntity();
            Assert.assertEquals(secureHttpClient.getPrincipal() + "@" + hostname, EntityUtils.toString(httpEntity));

            EntityUtils.consume(httpEntity);

            secureHttpClient.setLoggedIn(true);
        } else {
            // Unknown principal (cannot be mapped to a Resource ID) or manipulated ticket
            Assert.assertEquals("Principal should not be mapped [" + ticketValidationUrl + "]",
                    HttpServletResponse.SC_NOT_FOUND, httpResponse.getStatusLine().getStatusCode());

            HttpUriRequest currentReq = (HttpUriRequest) httpClientContext.getRequest();
            HttpHost currentHost = httpClientContext.getTargetHost();
            String currentUrl = (currentReq.getURI().isAbsolute())
                    ? currentReq.getURI().toString()
                    : (currentHost.toURI() + currentReq.getURI());
            Assert.assertEquals(failedUrl, currentUrl);
            httpEntity = httpResponse.getEntity();

            EntityUtils.consume(httpEntity);

            secureHttpClient.setLoggedIn(false);
        }
    }

    public void casLoginWithInvalidTicket(final SecureHttpClient secureHttpClient) throws Exception {
        casLogin(secureHttpClient, true);
    }

    public void casLoginWithTicket(final SecureHttpClient secureHttpClient) throws Exception {

        CloseableHttpClient httpClient = secureHttpClient.getHttpClient();
        HttpClientContext httpClientContext = secureHttpClient.getHttpClientContext();

        String casLoginUrl = CAS_LOGIN_URL + "?" + LOCALE + "&service="
                + URLEncoder.encode(helloServiceUrl, StandardCharsets.UTF_8.displayName());
        HttpGet httpGet = new HttpGet(casLoginUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals("Failed to access URL [" + casLoginUrl + "]",
                HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
        EntityUtils.consume(httpResponse.getEntity());
    }

    public void casLogout(final SecureHttpClient secureHttpClient) throws Exception {
        Assert.assertTrue(secureHttpClient.isLoggedIn());

        CloseableHttpClient httpClient = secureHttpClient.getHttpClient();
        HttpClientContext httpClientContext = secureHttpClient.getHttpClientContext();

        HttpGet httpGet = new HttpGet(CAS_LOGOUT_URL);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals("Failed to access URL [" + CAS_LOGOUT_URL + "]",
                HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
        EntityUtils.consume(httpResponse.getEntity());
        Thread.sleep(1000); // wait for the CAS logout request to be processed asynchronously

        secureHttpClient.setLoggedIn(false);
    }

    public void deactivate() throws Exception {
        if (server != null) {
            server.stop();
            server.destroy();
        }
    }

    private String extractFromResponse(final String response, final String paramId) throws Exception {
        int start = response.indexOf(paramId);
        if (start != -1) {
            start += paramId.length();
            int end = response.indexOf("\"", start);
            String value = response.substring(start, end);
            return value;
        }
        return null;
    }

    public String getFailedUrl() {
        return failedUrl;
    }

    public String getHelloServiceUrl() {
        return helloServiceUrl;
    }

    private String[] getHiddenParamsFromCasLoginForm(final CloseableHttpClient httpClient,
            final HttpClientContext httpClientContext, final String casLoginUrl) throws Exception {

        HttpGet httpGet = new HttpGet(casLoginUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals("Failed to access URL [" + casLoginUrl + "]",
                HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());

        String loginResponse = EntityUtils.toString(httpResponse.getEntity());

        String lt = extractFromResponse(loginResponse, CAS_LT_BEGIN);
        Assert.assertNotNull(lt);

        String execution = extractFromResponse(loginResponse, CAS_EXECUTION_BEGIN);
        Assert.assertNotNull(execution);

        EntityUtils.consume(httpResponse.getEntity());
        return new String[] { lt, execution };
    }

    private String getLocale(final HttpClientContext httpClientContext) {
        List<Cookie> cookies = httpClientContext.getCookieStore().getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE")) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public String getLoggedOutUrl() {
        return loggedOutUrl;
    }

    public String getSessionLogoutUrl() {
        return sessionLogoutUrl;
    }

    public void sessionLogout(final SecureHttpClient secureHttpClient) throws Exception {

        CloseableHttpClient httpClient = secureHttpClient.getHttpClient();
        HttpClientContext httpClientContext = secureHttpClient.getHttpClientContext();

        HttpGet httpGet = new HttpGet(sessionLogoutUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals("URL should not be accessed [" + sessionLogoutUrl + "]",
                HttpServletResponse.SC_NOT_FOUND, httpResponse.getStatusLine().getStatusCode());

        HttpUriRequest currentReq = (HttpUriRequest) httpClientContext.getRequest();
        HttpHost currentHost = httpClientContext.getTargetHost();
        String currentUrl = (currentReq.getURI().isAbsolute())
                ? currentReq.getURI().toString()
                : (currentHost.toURI() + currentReq.getURI());
        Assert.assertEquals(loggedOutUrl, currentUrl);
        EntityUtils.consume(httpResponse.getEntity());
    }

    public void setPort() {
        if (!server.isStopped()) {
            throw new IllegalStateException("Server must be stopped before configuring port");
        }
        Connector[] connectors = server.getConnectors();
        for (Connector connector : connectors) {
            if (connector instanceof AbstractNetworkConnector) {
                ((AbstractNetworkConnector) connector).setPort(port);
            }
        }
    }

    public void start() throws Exception {
        server.start();
    }

    public void stop() throws Exception {
        server.stop();
    }

}
