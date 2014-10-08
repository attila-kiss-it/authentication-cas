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
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.osgi.framework.BundleContext;

public class SecureHttpClient {

    private final CloseableHttpClient httpClient;

    private final HttpClientContext httpClientContext;

    private final String principal;

    private boolean loggedIn = false;

    public SecureHttpClient(final String principal, final BundleContext bundleContext) throws Exception {
        this.principal = principal;

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

    public void close() throws IOException {
        httpClient.close();
    }

    public CloseableHttpClient getHttpClient() {
        return httpClient;
    }

    public HttpClientContext getHttpClientContext() {
        return httpClientContext;
    }

    public String getPrincipal() {
        return principal;
    }

    public boolean isLoggedIn() {
        return loggedIn;
    }

    public void setLoggedIn(final boolean loggedIn) {
        this.loggedIn = loggedIn;
    }

}
