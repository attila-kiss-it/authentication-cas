/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.biz)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.everit.authentication.cas;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.io.IOUtils;
import org.everit.authentication.http.session.AuthenticationSessionAttributeNames;
import org.everit.resource.resolver.ResourceIdResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

/**
 * The implementation that supports CAS authentication.
 * <p>
 * <b>Implemented interfaces</b>
 * </p>
 * <ul>
 * <li><b>{@link Filter}</b>: Handles the CAS service ticket validation and CAS logout request
 * processing.</li>
 * <li><b>{@link HttpSessionListener}</b>: Clears the {@link CasHttpSessionRegistry} when a
 * {@link HttpSession} is invalidated.</li>
 * </ul>
 * <p>
 * It is recommended to use this component in pair with
 * <a href="https://github.com/everit-org/authentication-http-session">authentication-http-session
 * </a>
 * </p>
 */
public class CasAuthentication implements
    Filter,
    HttpSessionListener {

  /**
   * Simple {@link DefaultHandler} extension.
   */
  private static class DefaultHandlerExt extends DefaultHandler {

    private StringBuilder builder;

    private String elementName;

    private boolean foundElement = false;

    /**
     * Constructor.
     *
     * @param builder
     *          the {@link StringBuilder} instance. Cannot be null.
     * @param elementName
     *          the name of the queried element
     */
    DefaultHandlerExt(final StringBuilder builder, final String elementName) {
      this.builder = Objects.requireNonNull(builder, "builder cannot be null");
      this.elementName = elementName;
    }

    @Override
    public void characters(final char[] ch, final int start, final int length)
        throws SAXException {
      if (foundElement) {
        builder.append(ch, start, length);
      }
    }

    @Override
    public void endElement(final String uri, final String localName, final String qName)
        throws SAXException {
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

  }

  /**
   * The element name in the failed service ticket validation response sent by the CAS server that
   * contains the message why the authentication failed.
   */
  private static final String AUTHENTICATION_FAILURE = "authenticationFailure";

  /**
   * The request parameter name used to specify the locale of the user when communicating with the
   * CAS server.
   */
  private static final String LOCALE = "locale";

  private static final Logger LOGGER = LoggerFactory.getLogger(CasAuthentication.class);

  /**
   * The template of the CAS service ticket validation URL. Parameters in order:
   * <ul>
   * <li>1: CAS server service ticket validation URL, for e.g.:
   * https://mycas.com/cas/serviceValidate</li>
   * <li>2: The URL encoded service URL, for e.g.: http://myapp.com/hello?foo=bar. The user will be
   * redirected to this URL after a successful validation.</li>
   * <li>3: The service ticket sent by the CAS server.</li>
   * </ul>
   */
  private static final String SERVICE_TICKET_VALIDATOR_URL_TEMPLATE =
      "%1$s?service=%2$s&ticket=%3$s";

  /**
   * The element name in logout request sent by the CAS server that contains the invalidated service
   * ticket.
   */
  private static final String SESSION_INDEX = "SessionIndex";

  /**
   * The element name in the successful service ticket validation response sent by the CAS server
   * that contains the name/principal of the authenticated user.
   */
  private static final String USER = "user";

  private final AuthenticationSessionAttributeNames authenticationSessionAttributeNames;

  private final CasHttpSessionRegistry casHttpSessionRegistry = new CasHttpSessionRegistry();

  /**
   * The service ticket validation URL of the CAS server.
   */
  private final String casServiceTicketValidatorUrl;

  /**
   * The URL where the user will be redirected in case of failures.
   */
  private final String failureUrl;

  /**
   * The HTTP request parameter name used by the CAS server when a Service Ticket (ST) is
   * invalidated due to logout.
   */
  private final String requestParamNameLogoutRequest;

  /**
   * The HTTP request parameter name used by the CAS server when it sends the Service Ticket (ST)
   * for validation to the protected application.
   */
  private final String requestParamNameServiceTicket;

  private final ResourceIdResolver resourceIdResolver;

  private final SAXParserFactory saxParserFactory;

  /**
   * Constructor.
   *
   * @throws NullPointerException
   *           if one of the parameter is <code>null</code>.
   */
  public CasAuthentication(
      final String casServiceTicketValidatorUrl,
      final String requestParamNameServiceTicket,
      final String requestParamNameLogoutRequest,
      final String failureUrl,
      final ResourceIdResolver resourceIdResolver,
      final AuthenticationSessionAttributeNames authenticationSessionAttributeNames,
      final SAXParserFactory saxParserFactory) {
    this.casServiceTicketValidatorUrl = Objects.requireNonNull(casServiceTicketValidatorUrl,
        "casServiceTicketValidatorUrl cannot be null");
    this.failureUrl = Objects.requireNonNull(failureUrl,
        "failureUrl cannot be null");
    this.authenticationSessionAttributeNames = Objects.requireNonNull(
        authenticationSessionAttributeNames,
        "authenticationSessionAttributeNames cannot be null");
    this.resourceIdResolver = Objects.requireNonNull(resourceIdResolver,
        "resourceIdResolver cannot be null");
    this.saxParserFactory = Objects.requireNonNull(saxParserFactory,
        "saxParserFactory cannot be null");
    this.requestParamNameLogoutRequest = Objects.requireNonNull(requestParamNameLogoutRequest,
        "requestParamNameLogoutRequest cannot be null");
    this.requestParamNameServiceTicket = Objects.requireNonNull(requestParamNameServiceTicket,
        "requestParamNameServiceTicket cannot be null");
  }

  /**
   * Creates the service URL forwarded to the CAS server as "service" parameter in case of service
   * ticket validation. This URL will be used to redirect the user if the service ticket validation
   * succeeds.
   *
   * @param httpServletRequest
   *          the request used to build the service URL
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
        queryString =
            queryString.substring(0, queryString.indexOf("&" + requestParamNameServiceTicket));
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
   * The method that processes the request is filter's url pattern matches the request. This method
   * handles one of the followings in order:
   * <ul>
   * <li>Performs a CAS service ticket validation if the request contains a service ticket named by
   * {@link #requestParamNameServiceTicket}.</li>
   * <li>Processes a back channel logout initiated by the CAS server if the request is POST request
   * and contains a parameter named by {@link #requestParamNameLogoutRequest}.</li>
   * <li>Invokes further the {@link FilterChain}.</li>
   * </ul>
   */
  @Override
  public void doFilter(final ServletRequest request, final ServletResponse response,
      final FilterChain chain)
          throws IOException, ServletException {

    HttpServletRequest httpServletRequest = (HttpServletRequest) request;

    String serviceTicket = getRequestParameter(httpServletRequest, requestParamNameServiceTicket);

    if (serviceTicket != null) {
      HttpServletResponse httpServletResponse = (HttpServletResponse) response;
      performServiceTicketValidation(httpServletRequest, httpServletResponse, serviceTicket);

    } else if (isCasLogoutRequest(httpServletRequest)) {
      processBackChannelLogout(httpServletRequest);

    } else {
      // Go further in the filter chain if the request does not contain the service ticket neither a
      // back channel
      // logout request
      chain.doFilter(request, response);
    }

  }

  /**
   * Returns the value of a request parameter if available.
   *
   * @param httpServletRequest
   *          the request to check for the parameter.
   * @param name
   *          the name of the parameter to check
   * @return the value of the requested parameter if available and not empty, otherwise
   *         <code>null</code>
   */
  private String getRequestParameter(final HttpServletRequest httpServletRequest,
      final String name) {
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

  /**
   * Returns the value of an XML element. This method is used to process the XMLs sent by the CAS
   * server.
   *
   * @param xmlAsString
   *          the XML string to process
   * @param elementName
   *          the name of the queried element
   * @return the value assigned to the queried element name
   * @throws RuntimeException
   *           if any error occurs during the parsing of the XML string
   */
  private String getTextForElement(final String xmlAsString, final String elementName) {

    XMLReader xmlReader;
    try {
      xmlReader = saxParserFactory.newSAXParser().getXMLReader();
      xmlReader.setFeature("http://xml.org/sax/features/namespaces", true);
      xmlReader.setFeature("http://xml.org/sax/features/namespace-prefixes", false);
      xmlReader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    } catch (SAXException | ParserConfigurationException e) {
      throw new RuntimeException("Unable to create XMLReader", e);
    }

    StringBuilder builder = new StringBuilder();

    DefaultHandler handler = new DefaultHandlerExt(builder, elementName);

    xmlReader.setContentHandler(handler);
    xmlReader.setErrorHandler(handler);

    try {
      xmlReader.parse(new InputSource(new StringReader(xmlAsString)));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return builder.toString();
  }

  @Override
  public void init(final FilterConfig filterConfig) throws ServletException {
    // Nothing to do here.
  }

  /**
   * Checks if the request is a CAS logout request.
   *
   * @param httpServletRequest
   *          the request to check
   * @return <code>true</code> if the request is a POST and a parameter with key
   *         {@link #requestParamNameLogoutRequest} exists in the request, otherwise
   *         <code>false</code>
   */
  private boolean isCasLogoutRequest(final HttpServletRequest httpServletRequest) {
    return httpServletRequest.getMethod().equals("POST")
        && httpServletRequest.getParameterMap().containsKey(requestParamNameLogoutRequest);
  }

  /**
   * Checks if the query string of the request contains the given name.
   *
   * @param httpServletRequest
   *          the request to check
   * @param name
   *          the name to check with
   * @return <code>true</code> if the query string is not <code>null</code> and contains the
   *         <code>name</code> argument, otherwise <code>false</code>
   */
  private boolean isRequestContains(final HttpServletRequest httpServletRequest,
      final String name) {
    String queryString = httpServletRequest.getQueryString();
    return (queryString != null) && queryString.contains(name);
  }

  /**
   * Performs a CAS service ticket validation. The following tasks are done if the service ticket is
   * valid:
   * <ul>
   * <li>The authenticated username/principal sent by the CAS server is mapped to a Resource ID.
   * </li>
   * <li>The mapped Resource ID is added to the {@link HttpSession} with the name provided by the
   * {@link AuthenticationSessionAttributeNames#authenticatedResourceId()} method. This Resource ID
   * will be picked up by the {@link Filter} provided by the
   * <a href="https://github.com/everit-org/authentication-http-session">authentication-http-session
   * </a> component and that filter will execute the authenticated process in the name of the
   * authenticated user.</li>
   * <li>A {@link CasHttpSessionActivationListener} is also registered to the session to handle
   * session passivation and activation events (for e.g. in case of persistent sessions).</li>
   * <li>The {@link HttpSession} is registered to the {@link CasHttpSessionRegistry} to be able to
   * handle CAS logout requests (invalidate the proper session belonging to the service ticket).
   * </li>
   * <li>Redirects the response to the service URL.</li>
   * </ul>
   */
  private void performServiceTicketValidation(final HttpServletRequest req,
      final HttpServletResponse resp, final String serviceTicket)
          throws IOException {

    String serviceUrl = createServiceUrl(req);
    String locale = getRequestParameter(req, LOCALE);

    String principal;
    try {
      principal = validateServiceTicket(serviceUrl, serviceTicket, locale);
    } catch (TicketValidationException e) {
      redirectToFailedUrl(resp, e.getMessage());
      return;
    }

    Optional<Long> optionalAuthenticatedResourceId = resourceIdResolver.getResourceId(principal);
    if (!optionalAuthenticatedResourceId.isPresent()) {
      redirectToFailedUrl(resp,
          "Principal [" + principal + "] cannot be mapped to Resource ID");
      return;
    }

    long authenticatedResourceId = optionalAuthenticatedResourceId.get();
    HttpSession httpSession = req.getSession();
    httpSession.setAttribute(
        authenticationSessionAttributeNames.authenticatedResourceId(),
        authenticatedResourceId);

    casHttpSessionRegistry.put(httpSession, serviceTicket);

    resp.sendRedirect(serviceUrl);

  }

  /**
   * Processes the CAS (back channel) logout requests. It retrieves the invalidated service ticket
   * from the logout request and invalidates the {@link HttpSession} assigned to that service
   * ticket.
   */
  private void processBackChannelLogout(final HttpServletRequest httpServletRequest)
      throws IOException {

    String logoutRequest = httpServletRequest.getParameter(requestParamNameLogoutRequest);
    String sessionIndex = getTextForElement(logoutRequest, SESSION_INDEX);

    casHttpSessionRegistry.removeByServiceTicket(sessionIndex)
        .ifPresent((httpSession) -> {
          try {
            httpSession.invalidate();
          } catch (IllegalStateException e) {
            LOGGER.debug(e.getMessage(), e);
          }
        });
  }

  private void redirectToFailedUrl(final HttpServletResponse resp, final String message)
      throws IOException {
    LOGGER.info(message);
    resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    resp.sendRedirect(failureUrl);
  }

  @Override
  public void sessionCreated(final HttpSessionEvent httpSessionEvent) {
    HttpSession httpSession = httpSessionEvent.getSession();
    casHttpSessionRegistry.putSession(httpSession);
  }

  /**
   * When an {@link HttpSession} is destroyed it must be removed from the
   * {@link CasHttpSessionRegistry}.
   */
  @Override
  public void sessionDestroyed(final HttpSessionEvent httpSessionEvent) {
    HttpSession httpSession = httpSessionEvent.getSession();
    casHttpSessionRegistry.removeBySession(httpSession);
  }

  /**
   * Validates a CAS service ticket and returns the username/principal belonging to that ticket.
   *
   * @param serviceUrl
   *          the service URL used to validate the service ticket
   * @param serviceTicket
   *          the service ticket to validate
   * @param locale
   *          the locale of the user used in the communication with the CAS server
   * @return the authenticated (in case of valid service ticket) username/principal
   * @throws IOException
   *           if an input or output exception occurs
   * @throws TicketValidationException
   *           if the ticket validation fails
   */
  private String validateServiceTicket(final String serviceUrl, final String serviceTicket,
      final String locale)
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
      if (!error.trim().isEmpty()) {
        throw new TicketValidationException(error.trim());
      }
      return getTextForElement(response, USER);
    }

  }

}
