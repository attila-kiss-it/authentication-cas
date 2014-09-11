/**
 * This file is part of Everit - HTML form-based authentication tests.
 *
 * Everit - HTML form-based authentication tests is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - HTML form-based authentication tests is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - HTML form-based authentication tests.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.authentication.http.form.tests;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.everit.osgi.authentication.context.AuthenticationContext;
import org.everit.osgi.authentication.simple.SimpleSubject;
import org.everit.osgi.authentication.simple.SimpleSubjectManager;
import org.everit.osgi.dev.testrunner.TestDuringDevelopment;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.everit.osgi.resource.ResourceService;
import org.junit.Assert;
import org.junit.Test;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;

@Component(name = "FormAuthenticationTest", immediate = true, configurationFactory = false,
        policy = ConfigurationPolicy.OPTIONAL)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "FormAuthenticationTest"),
        @Property(name = "httpService.target", value = "(org.osgi.service.http.port=*)"),
        @Property(name = "simpleSubjectManager.target"),
        @Property(name = "resourceService.target"),
        @Property(name = "authenticationContext.target")
})
@Service(value = FormAuthenticationTestComponent.class)
public class FormAuthenticationTestComponent {

    @Reference(bind = "setHttpService")
    private HttpService httpService;

    @Reference(bind = "setSimpleSubjectManager")
    private SimpleSubjectManager simpleSubjectManager;

    @Reference(bind = "setResourceService")
    private ResourceService resourceService;

    @Reference(bind = "setAuthenticationContext")
    private AuthenticationContext authenticationContext;

    private int port;

    private String helloUrl;

    private String failedUrl;

    private String loginActionUrl;

    private String username = "Aladdin";

    private String password = "open sesame";

    private long authenticatedResourceId;

    private long defaultResourceId;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties)
            throws Exception {
        helloUrl = "http://localhost:" + port + "/hello";
        failedUrl = "http://localhost:" + port + "/bello";
        loginActionUrl = "http://localhost:" + port + "/login-action";

        long resourceId = resourceService.createResource();
        simpleSubjectManager.delete(username);
        SimpleSubject simpleSubject = simpleSubjectManager.create(resourceId, username, password);
        authenticatedResourceId = simpleSubject.getResourceId();
        defaultResourceId = authenticationContext.getDefaultResourceId();
        Thread.sleep(5000); // FIXME waiting for the whiteboard pattern to register the filters and servlets
    }

    private void hello(final HttpContext httpContext, final long expectedResourceId)
            throws IOException {
        HttpClient httpClient = new DefaultHttpClient();
        HttpGet httpGet = new HttpGet(helloUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet, httpContext);
        Assert.assertEquals(HttpServletResponse.SC_OK, httpResponse.getStatusLine().getStatusCode());
        HttpEntity responseEntity = httpResponse.getEntity();
        InputStream inputStream = responseEntity.getContent();
        StringWriter writer = new StringWriter();
        IOUtils.copy(inputStream, writer);
        String responseBodyAsString = writer.toString();
        Assert.assertEquals(expectedResourceId, Long.valueOf(responseBodyAsString).longValue());
    }

    private void login(final HttpContext httpContext, final String u, final String p, final String s, final String f,
            final String expectedLocation)
            throws Exception {
        HttpClient httpClient = new DefaultHttpClient();
        HttpPost httpPost = new HttpPost(loginActionUrl);
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair("username", u));
        parameters.add(new BasicNameValuePair("password", p));
        parameters.add(new BasicNameValuePair("successUrl", s));
        parameters.add(new BasicNameValuePair("failedUrl", f));
        HttpEntity entity = new UrlEncodedFormEntity(parameters);
        httpPost.setEntity(entity);
        HttpResponse httpResponse = httpClient.execute(httpPost, httpContext);
        Assert.assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, httpResponse.getStatusLine().getStatusCode());
        Header locationHeader = httpResponse.getFirstHeader("Location");
        Assert.assertEquals(expectedLocation, locationHeader.getValue());
    }

    public void setAuthenticationContext(final AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public void setHttpService(final HttpService httpService, final Map<String, Object> properties) {
        this.httpService = httpService;
        port = Integer.valueOf((String) properties.get("org.osgi.service.http.port"));
        port--; // TODO port must be decremented because the port of the Server is less than the value of the service
        // portperty queried above
    }

    public void setResourceService(final ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    public void setSimpleSubjectManager(final SimpleSubjectManager simpleSubjectManager) {
        this.simpleSubjectManager = simpleSubjectManager;
    }

    @Test
    @TestDuringDevelopment
    public void testAccessHelloPage() throws Exception {
        CookieStore cookieStore = new BasicCookieStore();
        HttpContext httpContext = new BasicHttpContext();
        httpContext.setAttribute(ClientContext.COOKIE_STORE, cookieStore);

        hello(httpContext, defaultResourceId);
        login(httpContext, username, password + password, helloUrl, failedUrl, failedUrl);
        login(httpContext, username, password, helloUrl, failedUrl, helloUrl);
        hello(httpContext, authenticatedResourceId);
    }

}
