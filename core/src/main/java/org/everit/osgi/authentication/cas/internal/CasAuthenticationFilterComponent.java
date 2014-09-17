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
package org.everit.osgi.authentication.cas.internal;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.io.IOUtils;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.everit.osgi.authentication.cas.CasAuthenticationConstants;
import org.everit.osgi.authentication.cas.CasHttpSessionRegistry;
import org.everit.osgi.authentication.http.session.AuthenticationSessionAttributeNames;
import org.everit.osgi.resource.resolver.ResourceIdResolver;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.log.LogService;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

@Component(name = CasAuthenticationConstants.SERVICE_FACTORYPID_CAS_AUTHENTICATION_FILTER, metatype = true,
        configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = Constants.SERVICE_DESCRIPTION, propertyPrivate = false,
                value = CasAuthenticationConstants.DEFAULT_SERVICE_DESCRIPTION_CAS_AUTHENTICATION_FILTER),
        @Property(name = CasAuthenticationConstants.PROP_CAS_SERVICE_TICKET_VALIDATION_URL,
                value = CasAuthenticationConstants.DEFAULT_CAS_SERVICE_TICKET_VALIDATION_URL),
        @Property(name = CasAuthenticationConstants.PROP_REQ_PARAM_NAME_SERVICE_TICKET,
                value = CasAuthenticationConstants.DEFAULT_REQ_PARAM_NAME_SERVICE_TICKET),
        @Property(name = CasAuthenticationConstants.PROP_REQ_PARAM_NAME_LOGOUT_REQUEST,
                value = CasAuthenticationConstants.DEFAULT_REQ_PARAM_NAME_LOGOUT_REQUEST),
        @Property(name = CasAuthenticationConstants.PROP_FAILURE_URL,
                value = CasAuthenticationConstants.DEFAULT_FAILURE_URL),
        @Property(name = CasAuthenticationConstants.PROP_AUTHENTICATION_SESSION_ATTRIBUTE_NAMES),
        @Property(name = CasAuthenticationConstants.PROP_RESOURCE_ID_RESOLVER),
        @Property(name = CasAuthenticationConstants.PROP_CAS_HTTP_SESSION_REGISTRY),
        @Property(name = CasAuthenticationConstants.PROP_LOG_SERVICE),
})
@Service
public class CasAuthenticationFilterComponent implements Filter {

    private static final String SERVICE_TICKET_VALIDATOR_URL_TEMPLATE = "%1$s?service=%2$s&ticket=%3$s";

    @Reference(bind = "setAuthenticationSessionAttributeNames")
    private AuthenticationSessionAttributeNames authenticationSessionAttributeNames;

    @Reference(bind = "setResourceIdResolver")
    private ResourceIdResolver resourceIdResolver;

    @Reference(bind = "setCasHttpSessionRegistry")
    private CasHttpSessionRegistry casHttpSessionRegistry;

    @Reference(bind = "setLogService")
    private LogService logService;

    private String casServiceTicketValidatorUrl;

    private String failureUrl;

    private String requestParamNameServiceTicket;

    private String requestParamNameLogoutRequest;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties) throws Exception {
        casServiceTicketValidatorUrl = getStringProperty(componentProperties,
                CasAuthenticationConstants.PROP_CAS_SERVICE_TICKET_VALIDATION_URL);
        failureUrl = getStringProperty(componentProperties,
                CasAuthenticationConstants.PROP_FAILURE_URL);
        requestParamNameServiceTicket = getStringProperty(componentProperties,
                CasAuthenticationConstants.PROP_REQ_PARAM_NAME_SERVICE_TICKET);
        requestParamNameLogoutRequest = getStringProperty(componentProperties,
                CasAuthenticationConstants.PROP_REQ_PARAM_NAME_LOGOUT_REQUEST);
    }

    private String constructServiceUrl(final HttpServletRequest httpServletRequest) {
        String queryString = httpServletRequest.getQueryString();
        if (queryString == null) {
            queryString = "";
        } else {
            int serviceTicketLocation = queryString.indexOf(requestParamNameServiceTicket);
            if (serviceTicketLocation <= 0) {
                queryString = "";
            } else {
                queryString = queryString.substring(0, queryString.indexOf("&" + requestParamNameServiceTicket));
                queryString = "?" + queryString;
            }
        }
        String serviceUrl = httpServletRequest.getRequestURL().append(queryString).toString();
        return serviceUrl;
    }

    private XMLReader createXmlReader() {
        try {
            XMLReader xmlReader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
            xmlReader.setFeature("http://xml.org/sax/features/namespaces", true);
            xmlReader.setFeature("http://xml.org/sax/features/namespace-prefixes", false);
            xmlReader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            return xmlReader;
        } catch (final Exception e) {
            throw new RuntimeException("Unable to create XMLReader", e);
        }
    }

    @Override
    public void destroy() {
        // Nothing to do here.
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        String serviceTicket = getRequestParameter(httpServletRequest, requestParamNameServiceTicket);

        if (serviceTicket != null) {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            performServiceTicketValidation(httpServletRequest, httpServletResponse, serviceTicket);

        } else if (isLogoutRequest(httpServletRequest)) {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            processBackChannelLogout(httpServletRequest, httpServletResponse);

        } else {
            // Go further in the filter chain if the request does not contain the service ticket neither a back channel
            // logout request
            chain.doFilter(request, response);
        }

    }

    private String getRequestParameter(final HttpServletRequest httpServletRequest, final String name) {
        if (!isRequestContains(httpServletRequest, name)) {
            return null;
        }
        String ticket = httpServletRequest.getParameter(name);
        if (ticket == null) {
            return null;
        }
        ticket = ticket.trim();
        if (ticket.isEmpty()) {
            return null;
        }
        return ticket;
    }

    private String getStringProperty(final Map<String, Object> componentProperties, final String propertyName)
            throws ConfigurationException {
        Object value = componentProperties.get(propertyName);
        if (value == null) {
            throw new ConfigurationException(propertyName, "property not defined");
        }
        return String.valueOf(value);
    }

    private String getTextForElement(final String xmlAsString, final String element) {

        XMLReader reader = createXmlReader();
        StringBuilder builder = new StringBuilder();

        DefaultHandler handler = new DefaultHandler() {

            private boolean foundElement = false;

            @Override
            public void characters(final char[] ch, final int start, final int length) throws SAXException {
                if (foundElement) {
                    builder.append(ch, start, length);
                }
            }

            @Override
            public void endElement(final String uri, final String localName, final String qName) throws SAXException {
                if (localName.equals(element)) {
                    foundElement = false;
                }
            }

            @Override
            public void startElement(final String uri, final String localName, final String qName,
                    final Attributes attributes) throws SAXException {
                if (localName.equals(element)) {
                    foundElement = true;
                }
            }
        };

        reader.setContentHandler(handler);
        reader.setErrorHandler(handler);

        try {
            reader.parse(new InputSource(new StringReader(xmlAsString)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return builder.toString();
    }

    private void handleError(final HttpServletResponse httpServletResponse, final String message,
            final Exception e) throws IOException {
        logService.log(LogService.LOG_ERROR, message, e);
        if (failureUrl != null) {
            httpServletResponse.sendRedirect(failureUrl);
        } else {
            httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, message);
        }
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        // Nothing to do here.
    }

    private boolean isLogoutRequest(final HttpServletRequest httpServletRequest) {
        return httpServletRequest.getMethod().equals("POST")
                && httpServletRequest.getParameterMap().containsKey(requestParamNameLogoutRequest);
    }

    private boolean isRequestContains(final HttpServletRequest httpServletRequest, final String name) {
        String queryString = httpServletRequest.getQueryString();
        return (queryString != null) && queryString.contains(name);
    }

    private void performServiceTicketValidation(final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse, final String serviceTicket) throws IOException {

        String serviceUrl = constructServiceUrl(httpServletRequest);

        try {
            String principal = validateServiceTicket(serviceUrl, serviceTicket);

            Long authenticatedResourceId = resourceIdResolver.getResourceId(principal)
                    .orElseThrow(() -> new IllegalStateException("The principal [" + principal
                            + "] of the valid service ticket cannot be mapped to Resource ID."
                            + " The session will not be assigned to any Resource ID."));

            HttpSession httpSession = httpServletRequest.getSession();
            httpSession.setAttribute(authenticationSessionAttributeNames.authenticatedResourceId(),
                    authenticatedResourceId);

            casHttpSessionRegistry.addSession(serviceTicket, httpSession);

            httpServletResponse.sendRedirect(serviceUrl);

        } catch (IllegalStateException | TicketValidationException e) {
            handleError(httpServletResponse, e.getMessage(), e);
        }
    }

    private void processBackChannelLogout(final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse) throws IOException {

        String logoutRequest = httpServletRequest.getParameter(requestParamNameLogoutRequest);
        String sessionIndex = getTextForElement(logoutRequest, "SessionIndex");

        casHttpSessionRegistry.removeByServiceTicket(sessionIndex)
                .ifPresent((httpSession) -> {
                    try {
                        httpSession.invalidate();
                    } catch (IllegalStateException e) {
                        logService.log(LogService.LOG_DEBUG, e.getMessage(), e);
                    }
                });
    }

    public void setAuthenticationSessionAttributeNames(
            final AuthenticationSessionAttributeNames authenticationSessionAttributeNames) {
        this.authenticationSessionAttributeNames = authenticationSessionAttributeNames;
    }

    public void setCasHttpSessionRegistry(final CasHttpSessionRegistry casHttpSessionRegistry) {
        this.casHttpSessionRegistry = casHttpSessionRegistry;
    }

    public void setLogService(final LogService logService) {
        this.logService = logService;
    }

    public void setResourceIdResolver(final ResourceIdResolver resourceIdResolver) {
        this.resourceIdResolver = resourceIdResolver;
    }

    private String validateServiceTicket(final String serviceUrl, final String serviceTicket)
            throws IOException, TicketValidationException {

        String validationUrl = String.format(SERVICE_TICKET_VALIDATOR_URL_TEMPLATE,
                casServiceTicketValidatorUrl,
                URLEncoder.encode(serviceUrl, StandardCharsets.UTF_8.displayName()),
                serviceTicket);

        HttpClient httpClient = new DefaultHttpClient();
        HttpGet httpGet = new HttpGet(validationUrl);
        HttpResponse httpResponse = httpClient.execute(httpGet);
        HttpEntity responseEntity = httpResponse.getEntity();
        InputStream inputStream = responseEntity.getContent();
        StringWriter writer = new StringWriter();
        IOUtils.copy(inputStream, writer);
        String response = writer.toString();
        String error = getTextForElement(response, "authenticationFailure");

        if ((error != null) && !error.trim().isEmpty()) {
            throw new TicketValidationException(error.trim());
        }

        String principal = getTextForElement(response, "user");
        return principal;
    }

}
