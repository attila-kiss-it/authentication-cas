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
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.io.IOUtils;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.authentication.cas.CasAuthenticationConstants;
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

/**
 * A component that supports CAS authentication. The following cases are handled by this component:
 * <ul>
 * <li><b>CAS service ticket validation</b>: If the request contains a CAS service ticket, it will be validated on the
 * CAS server by invoking its service ticket validation URL. If the ticket is valid and the returned principal
 * (username) can be mapped to a Resource ID, then the Resource ID will be assigned to the session.</li>
 * <li><b>CAS logout request processing</b>: If the request is a CAS logout request, then the session assigned to the
 * service ticket (received in the logout request) will be invalidated. The CAS server sends the logout request
 * asynchronously to the clients, therefore the session of the logout request is not the same as the session of the
 * user. The mapping of service tickets and sessions are handled by the {@link CasHttpSessionRegistry}.</li>
 * </ul>
 * <p>
 * <b>Implemented interfaces</b>
 * </p>
 * <ul>
 * <li><b>{@link Filter}</b>: Handles the CAS service ticket validation and CAS logout request processing.</li>
 * <li><b>{@link ServletContextListener}</b>: Registers and removes the {@link CasHttpSessionRegistry} to and from the
 * {@link ServletContext}.</li>
 * <li><b>{@link HttpSessionListener}</b>: Clears the {@link CasHttpSessionRegistry} when a {@link HttpSession} is
 * invalidated.</li>
 * <li><b>{@link HttpSessionAttributeListener}</b>: Registers and removes the {@link CasHttpSessionActivationListener}
 * to and from the {@link HttpSession} because it IS NOT {@link java.io.Serializable} and cannot be
 * instantiated/deserialized by a non-OSGi technology. Class loading problems can occur when deserializing this
 * {@link java.util.EventListener} if it is still in the {@link HttpSession} during serialization.</li>
 * </ul>
 * <p>
 * It is recommended to use this component in pair with <a
 * href="https://github.com/everit-org/authentication-http-session">authentication-http-session</a>
 * </p>
 */
@Component(name = CasAuthenticationConstants.SERVICE_FACTORYPID_CAS_AUTHENTICATION, metatype = true,
        configurationFactory = true, policy = ConfigurationPolicy.REQUIRE, immediate = true)
@Properties({
        @Property(name = Constants.SERVICE_DESCRIPTION, propertyPrivate = false,
                value = CasAuthenticationConstants.DEFAULT_SERVICE_DESCRIPTION_CAS_AUTHENTICATION),
        @Property(name = CasAuthenticationConstants.PROP_CAS_SERVICE_TICKET_VALIDATION_URL,
                value = CasAuthenticationConstants.DEFAULT_CAS_SERVICE_TICKET_VALIDATION_URL),
        @Property(name = CasAuthenticationConstants.PROP_FAILURE_URL,
                value = CasAuthenticationConstants.DEFAULT_FAILURE_URL),
        @Property(name = CasAuthenticationConstants.PROP_AUTHENTICATION_SESSION_ATTRIBUTE_NAMES),
        @Property(name = CasAuthenticationConstants.PROP_RESOURCE_ID_RESOLVER),
        @Property(name = CasAuthenticationConstants.PROP_SAX_PARSER_FACTORY),
        @Property(name = CasAuthenticationConstants.PROP_LOG_SERVICE),
})
@Service
public class CasAuthenticationComponent implements
        Filter,
        ServletContextListener,
        HttpSessionListener,
        HttpSessionAttributeListener {

    /**
     * The template of the CAS service ticket validation URL. Parameters in order:
     * <ul>
     * <li>1: CAS server service ticket validation URL, for e.g.: https://mycas.com/cas/serviceValidate</li>
     * <li>2: The URL encoded service URL, for e.g.: http://myapp.com/hello?foo=bar. The user will be redirected to this
     * URL after a successful validation.</li>
     * <li>3: The service ticket sent by the CAS server.</li>
     * </ul>
     */
    private static final String SERVICE_TICKET_VALIDATOR_URL_TEMPLATE = "%1$s?service=%2$s&ticket=%3$s";

    /**
     * The element name in logout request sent by the CAS server that contains the invalidated service ticket.
     */
    private static final String SESSION_INDEX = "SessionIndex";

    /**
     * The element name in the successful service ticket validation response sent by the CAS server that contains the
     * name/principal of the authenticated user.
     */
    private static final String USER = "user";

    /**
     * The element name in the failed service ticket validation response sent by the CAS server that contains the
     * message why the authentication failed.
     */
    private static final String AUTHENTICATION_FAILURE = "authenticationFailure";

    /**
     * The request parameter name used to specify the locale of the user when communicating with the CAS server.
     */
    private static final String LOCALE = "locale";

    /**
     * The default value of the {@link #requestParamNameServiceTicket}.
     */
    private static final String DEFAULT_REQ_PARAM_NAME_SERVICE_TICKET = "ticket";

    /**
     * The default value of the {@link #requestParamNameLogoutRequest}.
     */
    private static final String DEFAULT_REQ_PARAM_NAME_LOGOUT_REQUEST = "logoutRequest";

    @Reference(bind = "setAuthenticationSessionAttributeNames")
    private AuthenticationSessionAttributeNames authenticationSessionAttributeNames;

    @Reference(bind = "setResourceIdResolver")
    private ResourceIdResolver resourceIdResolver;

    @Reference(bind = "setSaxParserFactory")
    private SAXParserFactory saxParserFactory;

    @Reference(bind = "setLogService")
    private LogService logService;

    /**
     * The service ticket validation URL of the CAS server.
     */
    private String casServiceTicketValidatorUrl;

    /**
     * The URL where the user will be redirected in case of failures.
     */
    private String failureUrl;

    /**
     * The HTTP request parameter name used by the CAS server when it sends the Service Ticket (ST) for validation to
     * the protected application.
     */
    private String requestParamNameServiceTicket = DEFAULT_REQ_PARAM_NAME_SERVICE_TICKET;

    /**
     * The HTTP request parameter name used by the CAS server when a Service Ticket (ST) is invalidated due to logout.
     */
    private String requestParamNameLogoutRequest = DEFAULT_REQ_PARAM_NAME_LOGOUT_REQUEST;

    /**
     * The persistent identifier of the services.
     */
    private String servicePid;

    /**
     * {@link org.apache.felix.scr.annotations.Activate} method of the component. It collects the configured component
     * properties and stores it in the member variables.
     */
    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties) throws Exception {
        casServiceTicketValidatorUrl = getStringProperty(componentProperties,
                CasAuthenticationConstants.PROP_CAS_SERVICE_TICKET_VALIDATION_URL);
        failureUrl = getStringProperty(componentProperties,
                CasAuthenticationConstants.PROP_FAILURE_URL);
        servicePid = getStringProperty(componentProperties, Constants.SERVICE_PID);
    }

    /**
     * Handles the case when a special session attribute is added. If an attribute added (manually or when restoring a
     * persistent session) with name starting with
     * {@link CasHttpSessionActivationListener#SESSION_ATTR_NAME_SERVICE_PID_PREFIX} this listener method will:
     * <ul>
     * <li>Register a {@link CasHttpSessionActivationListener} instance to the session and remove the added session
     * attribute if the {@link CasHttpSessionActivationListener} IS NOT REGISTERED to the session already with the
     * Service PID stored in the session. This is necessary to re-register the EventListener when a session is restored
     * from its persistent state.</li>
     * <li>Remove the {@link CasHttpSessionActivationListener} instance from the session if the
     * {@link CasHttpSessionActivationListener} IS REGISTERED to the session already with the Service PID stored in the
     * session. This is necessary to remove the EventListener from the session before it will be Serialized, because the
     * {@link CasHttpSessionActivationListener} is not {@link java.io.Serializable} and cannot be
     * instantiated/deserialized by a non-OSGi technology</li>
     * </ul>
     */
    @Override
    public void attributeAdded(final HttpSessionBindingEvent event) {
        String addedAttributeName = event.getName();
        if (addedAttributeName.startsWith(CasHttpSessionActivationListener.SESSION_ATTR_NAME_SERVICE_PID_PREFIX)) {

            String servicePid = (String) event.getValue();
            String casHttpSessionActivationListenerSessionAttrName =
                    CasHttpSessionActivationListener.createSessionAttrNameInstance(servicePid);

            HttpSession httpSession = event.getSession();
            if (httpSession.getAttribute(casHttpSessionActivationListenerSessionAttrName) == null) {

                CasHttpSessionActivationListener.registerInstance(servicePid, httpSession);
                String attributeNameToRemove =
                        CasHttpSessionActivationListener.createSessionAttrNameServicePid(servicePid);
                if (attributeNameToRemove.equals(addedAttributeName)) {
                    httpSession.removeAttribute(attributeNameToRemove);
                }
            } else {
                CasHttpSessionActivationListener.removeInstance(servicePid, httpSession);
            }
        }
    }

    @Override
    public void attributeRemoved(final HttpSessionBindingEvent event) {
        // Nothing to do
    }

    @Override
    public void attributeReplaced(final HttpSessionBindingEvent event) {
        // Nothing to do
    }

    /**
     * Removes the previously registered {@link CasHttpSessionRegistry} from the {@link ServletContext} when it is
     * destroyed.
     */
    @Override
    public void contextDestroyed(final ServletContextEvent servletContextEvent) {
        ServletContext servletContext = servletContextEvent.getServletContext();
        CasHttpSessionRegistry.removeInstance(servicePid, servletContext);
    }

    /**
     * Registers the {@link CasHttpSessionRegistry} to the {@link ServletContext} when it is initialized.
     */
    @Override
    public void contextInitialized(final ServletContextEvent servletContextEvent) {
        ServletContext servletContext = servletContextEvent.getServletContext();
        CasHttpSessionRegistry.registerInstance(servicePid, servletContext);
    }

    /**
     * Creates the service URL forwarded to the CAS server as "service" parameter in case of service ticket validation.
     * This URL will be used to redirect the user if the service ticket validation succeeds.
     *
     * @param httpServletRequest
     *            the request used to build the service URL
     * @return the service URL
     */
    private String createServiceUrl(final HttpServletRequest httpServletRequest) {
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

    @Override
    public void destroy() {
        // Nothing to do here.
    }

    /**
     * The method that processes the request is filter's url pattern matches the requst. This method handles one of the
     * followings in order:
     * <ul>
     * <li>Performs a CAS service ticket validation if the request contains a service ticket named by
     * {@link #requestParamNameServiceTicket}.</li>
     * <li>Processes a back channel logout initiated by the CAS server if the request is POST request and contains a
     * parameter named by {@link #requestParamNameLogoutRequest}.</li>
     * <li>Invokes further the {@link FilterChain}.</li>
     * </ul>
     */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        String serviceTicket = getRequestParameter(httpServletRequest, requestParamNameServiceTicket);

        if (serviceTicket != null) {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            performServiceTicketValidation(httpServletRequest, httpServletResponse, serviceTicket);

        } else if (isCasLogoutRequest(httpServletRequest)) {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            processBackChannelLogout(httpServletRequest, httpServletResponse);

        } else {
            // Go further in the filter chain if the request does not contain the service ticket neither a back channel
            // logout request
            chain.doFilter(request, response);
        }

    }

    /**
     * Returns the value of a request parameter if available.
     *
     * @param httpServletRequest
     *            the request to check for the parameter.
     * @param name
     *            the name of the parameter to check
     * @return the value of the requested parameter if available and not empty, otherwise <code>null</code>
     */
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

    /**
     * Returns the value of an XML element. This method is used to process the XMLs sent by the CAS server.
     *
     * @param xmlAsString
     *            the XML string to process
     * @param elementName
     *            the name of the queried element
     * @return the value assigned to the queried element name
     * @throws RuntimeException
     *             if any error occurs during the parsing of the XML string
     */
    private String getTextForElement(final String xmlAsString, final String elementName) {

        XMLReader xmlReader;
        try {
            xmlReader = saxParserFactory.newSAXParser().getXMLReader();
            xmlReader.setFeature("http://xml.org/sax/features/namespaces", true);
            xmlReader.setFeature("http://xml.org/sax/features/namespace-prefixes", false);
            xmlReader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (final Exception e) {
            throw new RuntimeException("Unable to create XMLReader", e);
        }

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
                if (localName.equals(elementName)) {
                    foundElement = false;
                }
            }

            @Override
            public void startElement(final String uri, final String localName, final String qName,
                    final Attributes attributes) throws SAXException {
                if (localName.equals(elementName)) {
                    foundElement = true;
                }
            }
        };

        xmlReader.setContentHandler(handler);
        xmlReader.setErrorHandler(handler);

        try {
            xmlReader.parse(new InputSource(new StringReader(xmlAsString)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return builder.toString();
    }

    /**
     * Redirects the response to the configured {@link #failureUrl} and logs the given message and exception.
     *
     * @param httpServletResponse
     *            the response used to redirect
     * @param message
     *            the error message to log
     * @param e
     *            the exception to log
     * @throws IOException
     *             if an input or output exception occurs
     */
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

    /**
     * Checks if the request is a CAS logout request.
     *
     * @param httpServletRequest
     *            the request to check
     * @return <code>true</code> if the request is a POST and a parameter with key
     *         {@link #requestParamNameLogoutRequest} exists in the request, otherwise <code>false</code>
     */
    private boolean isCasLogoutRequest(final HttpServletRequest httpServletRequest) {
        return httpServletRequest.getMethod().equals("POST")
                && httpServletRequest.getParameterMap().containsKey(requestParamNameLogoutRequest);
    }

    /**
     * Checks if the query string of the request contains the given name.
     *
     * @param httpServletRequest
     *            the request to check
     * @param name
     *            the name to check with
     * @return <code>true</code> if the query string is not <code>null</code> and contains the <code>name</code>
     *         argument, otherwise <code>false</code>
     */
    private boolean isRequestContains(final HttpServletRequest httpServletRequest, final String name) {
        String queryString = httpServletRequest.getQueryString();
        return (queryString != null) && queryString.contains(name);
    }

    /**
     * Performs a CAS service ticket validation. The following tasks are done if the service ticket is valid:
     * <ul>
     * <li>The authenticated username/principal sent by the CAS server is mapped to a Resource ID.</li>
     * <li>The mapped Resource ID is added to the {@link HttpSession} with the name provided by the
     * {@link AuthenticationSessionAttributeNames#authenticatedResourceId()} method. This Resource ID will be picked up
     * by the {@link Filter} provided by the <a
     * href="https://github.com/everit-org/authentication-http-session">authentication-http-session</a> component and
     * that filter will execute the authenticated process in the name of the authenticated user.</li>
     * <li>A {@link CasHttpSessionActivationListener} is also registered to the session to handle session passivation
     * and activation events (for e.g. in case of persistent sessions).</li>
     * <li>The {@link HttpSession} is registered to the {@link CasHttpSessionRegistry} stored in the
     * {@link ServletContext} to be able to handle CAS logout requests (invalidate the proper session belonging to the
     * service ticket).</li>
     * <li>Redirects the response to the service URL.</li>
     * </ul>
     */
    private void performServiceTicketValidation(final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse, final String serviceTicket) throws IOException {

        String serviceUrl = createServiceUrl(httpServletRequest);
        String locale = getRequestParameter(httpServletRequest, LOCALE);

        try {
            String principal = validateServiceTicket(serviceUrl, serviceTicket, locale);

            Long authenticatedResourceId = resourceIdResolver.getResourceId(principal)
                    .orElseThrow(() -> new IllegalStateException("The principal [" + principal
                            + "] of the valid service ticket cannot be mapped to a Resource ID."
                            + " The session will not be assigned to any Resource ID."));

            HttpSession httpSession = httpServletRequest.getSession();
            httpSession.setAttribute(
                    authenticationSessionAttributeNames.authenticatedResourceId(),
                    authenticatedResourceId);

            CasHttpSessionActivationListener.registerInstance(servicePid, httpSession);

            ServletContext servletContext = httpServletRequest.getServletContext();
            CasHttpSessionRegistry casHttpSessionRegistry =
                    CasHttpSessionRegistry.getInstance(servicePid, servletContext);
            casHttpSessionRegistry.put(serviceTicket, httpSession);

            httpServletResponse.sendRedirect(serviceUrl);

        } catch (IllegalStateException | TicketValidationException e) {
            handleError(httpServletResponse, e.getMessage(), e);
        }
    }

    /**
     * Processes the CAS (back channel) logout requests. It retrieves the invalidated service ticket from the logout
     * request and invalidates the {@link HttpSession} assigned to that service ticket.
     */
    private void processBackChannelLogout(final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse) throws IOException {

        String logoutRequest = httpServletRequest.getParameter(requestParamNameLogoutRequest);
        String sessionIndex = getTextForElement(logoutRequest, SESSION_INDEX);

        ServletContext servletContext = httpServletRequest.getServletContext();
        CasHttpSessionRegistry casHttpSessionRegistry =
                CasHttpSessionRegistry.getInstance(servicePid, servletContext);

        casHttpSessionRegistry.removeByServiceTicket(sessionIndex)
                .ifPresent((httpSession) -> {
                    try {
                        httpSession.invalidate();
                    } catch (IllegalStateException e) {
                        logService.log(LogService.LOG_DEBUG, e.getMessage(), e);
                    }
                });
    }

    @Override
    public void sessionCreated(final HttpSessionEvent httpSessionEvent) {
        // Nothing to do here.
    }

    /**
     * When an {@link HttpSession} is destroyed it must be removed from the {@link CasHttpSessionRegistry}.
     */
    @Override
    public void sessionDestroyed(final HttpSessionEvent httpSessionEvent) {
        HttpSession httpSession = httpSessionEvent.getSession();
        ServletContext servletContext = httpSession.getServletContext();

        CasHttpSessionRegistry casHttpSessionRegistry =
                CasHttpSessionRegistry.getInstance(servicePid, servletContext);
        casHttpSessionRegistry.removeBySession(httpSession);
    }

    public void setAuthenticationSessionAttributeNames(
            final AuthenticationSessionAttributeNames authenticationSessionAttributeNames) {
        this.authenticationSessionAttributeNames = authenticationSessionAttributeNames;
    }

    public void setLogService(final LogService logService) {
        this.logService = logService;
    }

    public void setResourceIdResolver(final ResourceIdResolver resourceIdResolver) {
        this.resourceIdResolver = resourceIdResolver;
    }

    public void setSaxParserFactory(final SAXParserFactory saxParserFactory) {
        this.saxParserFactory = saxParserFactory;
    }

    /**
     * Validates a CAS service ticket and returns the username/principal belonging to that ticket.
     *
     * @param serviceUrl
     *            the service URL used to validate the service ticket
     * @param serviceTicket
     *            the service ticket to validate
     * @param locale
     *            the locale of the user used in the communication with the CAS server
     * @return the authenticated (in case of valid service ticket) username/principal
     * @throws IOException
     *             if an input or output exception occurs
     * @throws TicketValidationException
     *             if the ticket validation fails
     */
    private String validateServiceTicket(final String serviceUrl, final String serviceTicket, final String locale)
            throws IOException, TicketValidationException {

        String validationUrl = String.format(SERVICE_TICKET_VALIDATOR_URL_TEMPLATE,
                casServiceTicketValidatorUrl,
                URLEncoder.encode(serviceUrl, StandardCharsets.UTF_8.displayName()),
                serviceTicket);
        if (locale != null) {
            validationUrl = validationUrl + "&" + LOCALE + "=" + locale;
        }

        URL url = new URL(validationUrl);
        try (InputStream inputStream = url.openStream()) {
            StringWriter writer = new StringWriter();
            IOUtils.copy(inputStream, writer);
            String response = writer.toString();
            String error = getTextForElement(response, AUTHENTICATION_FAILURE);
            if ((error != null) && !error.trim().isEmpty()) {
                throw new TicketValidationException(error.trim());
            }
            return getTextForElement(response, USER);
        }

    }

}
