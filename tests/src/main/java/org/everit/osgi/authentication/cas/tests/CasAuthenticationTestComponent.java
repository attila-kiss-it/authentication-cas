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

import java.util.EventListener;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.Servlet;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.http.conn.HttpHostConnectException;
import org.everit.osgi.authentication.context.AuthenticationContext;
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

        @Property(name = "sessionAuthenticationFilter1.target"),
        @Property(name = "sessionLogoutServlet1.target"),
        @Property(name = "casAuthenticationFilter1.target"),
        @Property(name = "casAuthenticationEventListener1.target"),
        @Property(name = "authenticationContext1.target"),

        @Property(name = "sessionAuthenticationFilter2.target"),
        @Property(name = "sessionLogoutServlet2.target"),
        @Property(name = "casAuthenticationFilter2.target"),
        @Property(name = "casAuthenticationEventListener2.target"),
        @Property(name = "authenticationContext2.target"),

        @Property(name = "logService.target")
})
@Service(value = CasAuthenticationTestComponent.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CasAuthenticationTestComponent {

    private static final String APP1 = "127.0.0.1";

    private static final String APP2 = "127.0.0.2";

    @Reference(bind = "setSessionAuthenticationFilter1")
    private Filter sessionAuthenticationFilter1;

    @Reference(bind = "setSessionLogoutServlet1")
    private Servlet sessionLogoutServlet1;

    @Reference(bind = "setCasAuthenticationFilter1")
    private Filter casAuthenticationFilter1;

    @Reference(bind = "setCasAuthenticationEventListener1")
    private EventListener casAuthenticationEventListener1;

    @Reference(bind = "setAuthenticationContext1")
    private AuthenticationContext authenticationContext1;

    @Reference(bind = "setSessionAuthenticationFilter2")
    private Filter sessionAuthenticationFilter2;

    @Reference(bind = "setSessionLogoutServlet2")
    private Servlet sessionLogoutServlet2;

    @Reference(bind = "setCasAuthenticationFilter2")
    private Filter casAuthenticationFilter2;

    @Reference(bind = "setCasAuthenticationEventListener2")
    private EventListener casAuthenticationEventListener2;

    @Reference(bind = "setAuthenticationContext2")
    private AuthenticationContext authenticationContext2;

    @Reference(bind = "setLogService")
    private LogService logService;

    private BundleContext bundleContext;

    private SampleApp sampleApp1;

    private SampleApp sampleApp2;

    private SecureHttpClient johndoe;

    private SecureHttpClient janedoe;

    @Activate
    public void activate(final BundleContext bundleContext, final Map<String, Object> componentProperties)
            throws Exception {

        this.bundleContext = bundleContext;

        SampleApp.pingCasLoginUrl(bundleContext);

        sampleApp1 = new SampleApp(APP1, sessionAuthenticationFilter1, sessionLogoutServlet1,
                casAuthenticationFilter1, casAuthenticationEventListener1,
                authenticationContext1);

        sampleApp2 = new SampleApp(APP2, sessionAuthenticationFilter2, sessionLogoutServlet2,
                casAuthenticationFilter2, casAuthenticationEventListener2,
                authenticationContext2);
    }

    @After
    public void after() throws Exception {
        if ((johndoe != null) && johndoe.isLoggedIn()) {
            sampleApp1.casLogout(johndoe);
        }
        johndoe.close();
        if ((janedoe != null) && janedoe.isLoggedIn()) {
            sampleApp2.casLogout(janedoe);
        }
        janedoe.close();
    }

    @Before
    public void before() throws Exception {
        johndoe = new SecureHttpClient(CasResourceIdResolver.JOHNDOE, bundleContext);
        janedoe = new SecureHttpClient(CasResourceIdResolver.JANEDOE, bundleContext);
    }

    @Deactivate
    public void deactivate() throws Exception {
        after();
        sampleApp1.deactivate();
        sampleApp2.deactivate();
    }

    public void setAuthenticationContext1(final AuthenticationContext authenticationContext1) {
        this.authenticationContext1 = authenticationContext1;
    }

    public void setAuthenticationContext2(final AuthenticationContext authenticationContext2) {
        this.authenticationContext2 = authenticationContext2;
    }

    public void setCasAuthenticationEventListener1(final EventListener casAuthenticationEventListener1) {
        this.casAuthenticationEventListener1 = casAuthenticationEventListener1;
    }

    public void setCasAuthenticationEventListener2(final EventListener casAuthenticationEventListener2) {
        this.casAuthenticationEventListener2 = casAuthenticationEventListener2;
    }

    public void setCasAuthenticationFilter1(final Filter casAuthenticationFilter1) {
        this.casAuthenticationFilter1 = casAuthenticationFilter1;
    }

    public void setCasAuthenticationFilter2(final Filter casAuthenticationFilter2) {
        this.casAuthenticationFilter2 = casAuthenticationFilter2;
    }

    public void setLogService(final LogService logService) {
        this.logService = logService;
    }

    public void setSessionAuthenticationFilter1(final Filter sessionAuthenticationFilter1) {
        this.sessionAuthenticationFilter1 = sessionAuthenticationFilter1;
    }

    public void setSessionAuthenticationFilter2(final Filter sessionAuthenticationFilter2) {
        this.sessionAuthenticationFilter2 = sessionAuthenticationFilter2;
    }

    public void setSessionLogoutServlet1(final Servlet sessionLogoutServlet1) {
        this.sessionLogoutServlet1 = sessionLogoutServlet1;
    }

    public void setSessionLogoutServlet2(final Servlet sessionLogoutServlet2) {
        this.sessionLogoutServlet2 = sessionLogoutServlet2;
    }

    @Test
    public void test_01_SingleApp_AccessHelloPageWithInvalidTicket() throws Exception {
        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);
        sampleApp1.casLoginWithInvalidTicket(johndoe);
        Assert.assertFalse(johndoe.isLoggedIn());
    }

    @Test
    public void test_02_SingleApp_TryLoginWithUnmappedResourceId() throws Exception {
        SecureHttpClient unknown = new SecureHttpClient(HelloWorldServlet.UNKNOWN, bundleContext);
        sampleApp1.assertHello(unknown, HelloWorldServlet.GUEST);
        sampleApp1.casLogin(unknown);
        Assert.assertFalse(unknown.isLoggedIn());
        unknown.close();
    }

    @Test
    public void test_03_SingleApp_AccessHello() throws Exception {
        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);

        sampleApp1.casLogin(johndoe);
        Assert.assertTrue(johndoe.isLoggedIn());
        sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);
        sampleApp1.casLogout(johndoe);
        Assert.assertFalse(johndoe.isLoggedIn());
        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);

        sampleApp1.casLogin(johndoe);
        Assert.assertTrue(johndoe.isLoggedIn());
        sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);
        sampleApp1.sessionLogout(johndoe);
        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);
        sampleApp1.casLoginWithTicket(johndoe);
        sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);
        sampleApp1.casLogout(johndoe);
        Assert.assertFalse(johndoe.isLoggedIn());
        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);
    }

    @Test
    public void test_04_SingleApp_Restart() throws Exception {
        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);

        sampleApp1.casLogin(johndoe);
        Assert.assertTrue(johndoe.isLoggedIn());
        sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);

        sampleApp1.stop();
        try {
            sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);
            Assert.fail();
        } catch (HttpHostConnectException e) {
            Assert.assertTrue(e.getMessage().contains("Connection refused"));
        }
        sampleApp1.setPort(); // required to set the port of the server to the selected random port otherwise Jetty will
                              // chose an other random port
        sampleApp1.start();

        sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);
    }

    @Test
    public void test_05_SingleApp_MultipleClients() throws Exception {
        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);
        sampleApp1.assertHello(janedoe, HelloWorldServlet.GUEST);

        sampleApp1.casLogin(johndoe);
        Assert.assertTrue(johndoe.isLoggedIn());
        Assert.assertFalse(janedoe.isLoggedIn());

        sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);
        sampleApp1.assertHello(janedoe, HelloWorldServlet.GUEST);

        sampleApp1.casLogin(janedoe);
        Assert.assertTrue(johndoe.isLoggedIn());
        Assert.assertTrue(janedoe.isLoggedIn());

        sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);
        sampleApp1.assertHello(janedoe, CasResourceIdResolver.JANEDOE);

        sampleApp1.casLogout(johndoe);
        Assert.assertFalse(johndoe.isLoggedIn());
        Assert.assertTrue(janedoe.isLoggedIn());

        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);
        sampleApp1.assertHello(janedoe, CasResourceIdResolver.JANEDOE);

        sampleApp1.casLogout(janedoe);
        Assert.assertFalse(johndoe.isLoggedIn());
        Assert.assertFalse(janedoe.isLoggedIn());

        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);
        sampleApp1.assertHello(janedoe, HelloWorldServlet.GUEST);
    }

    @Test
    public void test_06_MultipleApp_OneClient() throws Exception {
        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);
        sampleApp2.assertHello(johndoe, HelloWorldServlet.GUEST);

        sampleApp1.casLogin(johndoe);
        Assert.assertTrue(johndoe.isLoggedIn());

        sampleApp2.casLoginWithTicket(johndoe);
        Assert.assertTrue(johndoe.isLoggedIn());

        sampleApp1.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);
        sampleApp2.assertHello(johndoe, CasResourceIdResolver.JOHNDOE);

        sampleApp1.casLogout(johndoe);
        Assert.assertFalse(johndoe.isLoggedIn());

        sampleApp1.assertHello(johndoe, HelloWorldServlet.GUEST);
        sampleApp2.assertHello(johndoe, HelloWorldServlet.GUEST);
    }

}
