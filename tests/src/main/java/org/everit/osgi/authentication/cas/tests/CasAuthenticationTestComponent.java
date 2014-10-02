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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EventListener;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.Filter;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.session.HashSessionManager;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.everit.osgi.authentication.http.cas.sample.CasResourceIdResolver;
import org.everit.osgi.authentication.http.cas.sample.HelloWorldServletComponent;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.osgi.framework.BundleContext;
import org.osgi.service.log.LogService;

@Component(name = "CasAuthenticationTest", metatype = true, configurationFactory = true,
        policy = ConfigurationPolicy.REQUIRE, immediate = true)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "CasAuthenticationTest"),
        @Property(name = "helloWorldServlet.target"),
        @Property(name = "sessionAuthenticationFilter.target"),
        @Property(name = "sessionLogoutServlet.target"),
        @Property(name = "casAuthenticationFilter.target"),
        @Property(name = "casEventListener.target"),
        @Property(name = "logService.target")
})
@Service(value = CasAuthenticationTestComponent.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CasAuthenticationTestComponent {

    private static final String INVALID_TICKET = "INVALID_TICKET";

    private static final String LOCALE = "locale=en";

    private static final String HELLO_SERVLET_ALIAS = "/hello";

    private static final String LOGOUT_SERVLET_ALIAS = "/logout";

    private static final String CAS_URL = "https://localhost:8443/cas";

    private static final String CAS_LOGIN_URL = CAS_URL + "/login";

    private static final String CAS_LOGOUT_URL = CAS_URL + "/logout";

    private static final String CAS_PING_FAILURE_MESSAGE = "CAS login URL [" + CAS_LOGIN_URL + "] not available! "
            + "Jetty should be executed by jetty-maven-plugin automatically in pre-integration-test phase "
            + "or manually using the 'mvn jetty:run' command (see pom.xml).";

    private static final String CAS_LT_BEGIN = "name=\"lt\" value=\"";

    private static final String CAS_EXECUTION_BEGIN = "name=\"execution\" value=\"";

    @Reference(bind = "setHelloWorldServlet")
    private Servlet helloWorldServlet;

    @Reference(bind = "setSessionAuthenticationFilter")
    private Filter sessionAuthenticationFilter;

    @Reference(bind = "setSessionLogoutServlet")
    private Servlet sessionLogoutServlet;

    @Reference(bind = "setCasAuthenticationFilter")
    private Filter casAuthenticationFilter;

    @Reference(bind = "setCasEventListener")
    private EventListener casEventListener;

    @Reference(bind = "setLogService")
    private LogService logService;

    private String helloServiceUrl;

    private String sessionLogoutUrl;

    private String loggedOutUrl;

    private String failedUrl;

    private Server server;

    private BundleContext bundleContext;

    private HttpClientContext httpClientContext;

    private CloseableHttpClient httpClient;

    private boolean loggedIn = false;

    @Activate
    public void activate(final BundleContext bundleContext, final Map<String, Object> componentProperties)
            throws Exception {

        this.bundleContext = bundleContext;

        initSecureHttpClient();
        pingCasLoginUrl();

        server = new Server(8081); // TODO use random port

        // Initialize servlet context
        ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);

        servletContextHandler.addFilter(
                new FilterHolder(sessionAuthenticationFilter), "/*", null);
        servletContextHandler.addFilter(
                new FilterHolder(casAuthenticationFilter), "/*", null);
        servletContextHandler.addServlet(
                new ServletHolder("helloWorldServlet", helloWorldServlet), HELLO_SERVLET_ALIAS);
        servletContextHandler.addServlet(
                new ServletHolder("sessionLogoutServlet", sessionLogoutServlet), LOGOUT_SERVLET_ALIAS);

        servletContextHandler.addEventListener(casEventListener);
        server.setHandler(servletContextHandler);

        // Initialize session management
        HashSessionManager sessionManager = new HashSessionManager();
        String sessionStoreDirecotry = System.getProperty("jetty.session.store.directory");
        sessionManager.setStoreDirectory(new File(sessionStoreDirecotry));
        sessionManager.setIdleSavePeriod(1);
        sessionManager.setSavePeriod(1);
        sessionManager.setLazyLoad(true); // required to initialize the servlet context before restoring the sessions
        sessionManager.addEventListener(casEventListener);

        SessionHandler sessionHandler = servletContextHandler.getSessionHandler();
        sessionHandler.setSessionManager(sessionManager);

        server.start();

        String testServerURI = server.getURI().toString();
        String testServerURL = testServerURI.substring(0, testServerURI.length() - 1);

        helloServiceUrl = testServerURL + HELLO_SERVLET_ALIAS;
        sessionLogoutUrl = testServerURL + "/logout";
        loggedOutUrl = testServerURL + "/logged-out.html";
        failedUrl = testServerURL + "/failed.html";
    }

    @After
    public void after() throws Exception {
        casLogout();
    }

    @Before
    public void before() throws Exception {
        initSecureHttpClient();
    }

    private void casLogin(final String username) throws Exception {

        String casLoginUrl = CAS_LOGIN_URL + "?" + LOCALE + "&service="
                + URLEncoder.encode(helloServiceUrl, StandardCharsets.UTF_8.displayName());
        String[] hiddenFormParams = getHiddenParamsFromCasLoginForm(casLoginUrl);

        // CAS login
        HttpPost httpPost = new HttpPost(casLoginUrl);
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("username", username));
        parameters.add(new BasicNameValuePair("password", username));
        parameters.add(new BasicNameValuePair("lt", hiddenFormParams[0]));
        parameters.add(new BasicNameValuePair("execution", hiddenFormParams[1]));
        parameters.add(new BasicNameValuePair("_eventId", "submit"));
        parameters.add(new BasicNameValuePair("submit", "LOGIN"));
        HttpEntity httpEntity = new UrlEncodedFormEntity(parameters);
        httpPost.setEntity(httpEntity);

        HttpResponse httpResponse = httpClient.execute(httpPost, httpClientContext);
        Assert.assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, httpResponse.getStatusLine().getStatusCode());
        Header locationHeader = httpResponse.getFirstHeader("Location");
        Assert.assertNotNull(locationHeader);
        String ticketValidationUrl = locationHeader.getValue();
        Assert.assertTrue(ticketValidationUrl.startsWith(helloServiceUrl));
        String locale = getLocale();
        Assert.assertNotNull(locale);
        EntityUtils.consume(httpResponse.getEntity());

        // CAS ticket validation
        ticketValidationUrl = ticketValidationUrl + "&locale=" + locale;

        if (username.equals(INVALID_TICKET)) {
            ticketValidationUrl = ticketValidationUrl.replace("ticket=", "ticket=X");
        }

        HttpGet httpGet = new HttpGet(ticketValidationUrl);
        httpResponse = httpClient.execute(httpGet, httpClientContext);

        if (username.equals(CasResourceIdResolver.JOHNDOE)) {
            Assert.assertEquals(HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());

            HttpUriRequest currentReq = (HttpUriRequest) httpClientContext.getRequest();
            HttpHost currentHost = httpClientContext.getTargetHost();
            String currentUrl = (currentReq.getURI().isAbsolute())
                    ? currentReq.getURI().toString()
                    : (currentHost.toURI() + currentReq.getURI());
            Assert.assertEquals(helloServiceUrl, currentUrl);
            httpEntity = httpResponse.getEntity();
            Assert.assertEquals(CasResourceIdResolver.JOHNDOE, EntityUtils.toString(httpEntity));

            EntityUtils.consume(httpEntity);

            loggedIn = true;
        } else {
            // Unknown principal (cannot be mapped to a Resource ID)
            Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, httpResponse.getStatusLine().getStatusCode());

            HttpUriRequest currentReq = (HttpUriRequest) httpClientContext.getRequest();
            HttpHost currentHost = httpClientContext.getTargetHost();
            String currentUrl = (currentReq.getURI().isAbsolute())
                    ? currentReq.getURI().toString()
                    : (currentHost.toURI() + currentReq.getURI());
            Assert.assertEquals(failedUrl, currentUrl);
            httpEntity = httpResponse.getEntity();

            EntityUtils.consume(httpEntity);

            loggedIn = false;
        }
    }

    private void casLoginWithTicket() throws Exception {
        String casLoginUrl = CAS_LOGIN_URL + "?" + LOCALE + "&service="
                + URLEncoder.encode(helloServiceUrl, StandardCharsets.UTF_8.displayName());
        HttpGet httpGet = new HttpGet(casLoginUrl);
        CloseableHttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals(HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
        EntityUtils.consume(httpResponse.getEntity());
    }

    private void casLogout() throws Exception {
        if (loggedIn) {
            HttpGet httpGet = new HttpGet(CAS_LOGOUT_URL);
            HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
            Assert.assertEquals(HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
            EntityUtils.consume(httpResponse.getEntity());
            Thread.sleep(1000); // wait for the CAS logout request to be processed asynchronously
        }
        loggedIn = false;
    }

    @Deactivate
    public void deactivate() throws Exception {
        casLogout();
        httpClient.close();
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

    private String[] getHiddenParamsFromCasLoginForm(final String casLoginUrl) throws Exception {

        HttpGet httpGet = new HttpGet(casLoginUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals(HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());

        String loginResponse = EntityUtils.toString(httpResponse.getEntity());

        String lt = extractFromResponse(loginResponse, CAS_LT_BEGIN);
        Assert.assertNotNull(lt);

        String execution = extractFromResponse(loginResponse, CAS_EXECUTION_BEGIN);
        Assert.assertNotNull(execution);

        EntityUtils.consume(httpResponse.getEntity());
        return new String[] { lt, execution };
    }

    private String getLocale() {
        List<Cookie> cookies = httpClientContext.getCookieStore().getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE")) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private void hello(final String expectedPrincipal) throws Exception {
        HttpGet httpGet = new HttpGet(helloServiceUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals(HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
        HttpEntity responseEntity = httpResponse.getEntity();
        InputStream inputStream = responseEntity.getContent();
        StringWriter writer = new StringWriter();
        IOUtils.copy(inputStream, writer);
        String responseBodyAsString = writer.toString();
        Assert.assertEquals(expectedPrincipal, responseBodyAsString);
        EntityUtils.consume(responseEntity);
    }

    private void initSecureHttpClient() throws Exception {
        httpClientContext = HttpClientContext.create();
        httpClientContext.setCookieStore(new BasicCookieStore());

        KeyStore trustStore = KeyStore.getInstance("jks");
        trustStore.load(
                bundleContext.getBundle().getResource("/jetty-keystore").openStream(), "changeit".toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, new SecureRandom());

        httpClient = HttpClientBuilder.create()
                .setSslcontext(sslContext)
                .setRedirectStrategy(new DefaultRedirectStrategy())
                .build();
    }

    private void pingCasLoginUrl() throws Exception {
        HttpGet httpGet = new HttpGet(CAS_LOGIN_URL + "?" + LOCALE);
        HttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpGet);
            Assert.assertEquals(CAS_PING_FAILURE_MESSAGE,
                    HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
        } catch (Exception e) {
            Assert.fail(CAS_PING_FAILURE_MESSAGE);
        }
        EntityUtils.consume(httpResponse.getEntity());
    }

    private void sessionLogout() throws Exception {
        HttpGet httpGet = new HttpGet(sessionLogoutUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpClientContext);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, httpResponse.getStatusLine().getStatusCode());

        HttpUriRequest currentReq = (HttpUriRequest) httpClientContext.getRequest();
        HttpHost currentHost = httpClientContext.getTargetHost();
        String currentUrl = (currentReq.getURI().isAbsolute())
                ? currentReq.getURI().toString()
                : (currentHost.toURI() + currentReq.getURI());
        Assert.assertEquals(loggedOutUrl, currentUrl);
        EntityUtils.consume(httpResponse.getEntity());
    }

    public void setCasAuthenticationFilter(final Filter casAuthenticationFilter) {
        this.casAuthenticationFilter = casAuthenticationFilter;
    }

    public void setCasEventListener(final EventListener casEventListener) {
        this.casEventListener = casEventListener;
    }

    public void setHelloWorldServlet(final Servlet helloWorldServlet) {
        this.helloWorldServlet = helloWorldServlet;
    }

    public void setLogService(final LogService logService) {
        this.logService = logService;
    }

    public void setSessionAuthenticationFilter(final Filter sessionAuthenticationFilter) {
        this.sessionAuthenticationFilter = sessionAuthenticationFilter;
    }

    public void setSessionLogoutServlet(final Servlet sessionLogoutServlet) {
        this.sessionLogoutServlet = sessionLogoutServlet;
    }

    @Test
    public void test_01_AccessHelloPageWithInvalidTicket() throws Exception {
        hello(HelloWorldServletComponent.GUEST);
        casLogin(INVALID_TICKET);
    }

    @Test
    public void test_02_AccessHelloPageWithJane() throws Exception {
        hello(HelloWorldServletComponent.GUEST);

        casLogin(HelloWorldServletComponent.JANEDOE);
    }

    @Test
    public void test_03_AccessHelloPageWithJohn() throws Exception {
        hello(HelloWorldServletComponent.GUEST);

        casLogin(CasResourceIdResolver.JOHNDOE);
        hello(CasResourceIdResolver.JOHNDOE);
        casLogout();
        hello(HelloWorldServletComponent.GUEST);

        casLogin(CasResourceIdResolver.JOHNDOE);
        hello(CasResourceIdResolver.JOHNDOE);
        sessionLogout();
        hello(HelloWorldServletComponent.GUEST);
        casLoginWithTicket();
        hello(CasResourceIdResolver.JOHNDOE);
        casLogout();
        hello(HelloWorldServletComponent.GUEST);
    }

    @Test
    public void test_04_ServerRestart() throws Exception {
        hello(HelloWorldServletComponent.GUEST);

        casLogin(CasResourceIdResolver.JOHNDOE);
        hello(CasResourceIdResolver.JOHNDOE);

        server.stop();
        // server.destroy();
        try {
            hello(CasResourceIdResolver.JOHNDOE);
            Assert.fail();
        } catch (HttpHostConnectException e) {
            Assert.assertTrue(e.getMessage().contains("Connection refused"));
        }
        server.start();

        hello(CasResourceIdResolver.JOHNDOE);
    }

}
