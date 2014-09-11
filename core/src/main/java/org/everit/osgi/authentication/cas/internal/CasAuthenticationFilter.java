package org.everit.osgi.authentication.cas.internal;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
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

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.everit.osgi.resource.resolver.ResourceIdResolver;
import org.osgi.service.log.LogService;

public class CasAuthenticationFilter implements Filter {

    private static final String SERVICE_TICKET_VALIDATOR_URL_TEMPLATE = "{}?service={}&ticket={}";

    private final ResourceIdResolver resourceIdResolver;

    private final String casServiceTicketValidatorUrl;

    private final String serviceUrl;

    private final String failureUrl;

    private final String sessionAttrNameAuthenticatedResourceId;

    private final String requestParamNameServiceTicket;

    private final LogService logService;

    public CasAuthenticationFilter(
            final ResourceIdResolver resourceIdResolver,
            final String casServiceTicketValidatorUrl,
            final String serviceUrl,
            final String failureUrl,
            final String sessionAttrNameAuthenticatedResourceId,
            final String requestParamNameServiceTicket,
            final LogService logService) {
        super();
        this.resourceIdResolver = resourceIdResolver;
        this.casServiceTicketValidatorUrl = casServiceTicketValidatorUrl;
        this.serviceUrl = serviceUrl;
        this.failureUrl = failureUrl;
        this.sessionAttrNameAuthenticatedResourceId = sessionAttrNameAuthenticatedResourceId;
        this.requestParamNameServiceTicket = requestParamNameServiceTicket;
        this.logService = logService;
    }

    @Override
    public void destroy() {
        // Nothing to do here.
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        String serviceTicket = getServiceTicket(httpServletRequest);

        if (serviceTicket != null) {

            HttpServletResponse httpServletResponse = (HttpServletResponse) response;

            try {
                String principal = validateServiceTicket(serviceTicket);
                Optional<Long> optionalAuthenticatedResourceId = resourceIdResolver.getResourceId(principal);

                if (optionalAuthenticatedResourceId.isPresent()) {
                    Long authenticatedResourceId = optionalAuthenticatedResourceId.get();
                    HttpSession httpSession = httpServletRequest.getSession();
                    httpSession.setAttribute(sessionAttrNameAuthenticatedResourceId, authenticatedResourceId);
                    httpServletResponse.sendRedirect(httpServletRequest.getRequestURL().toString());

                } else {
                    handleError(httpServletResponse, "The principal [" + principal
                            + "] of the valid service ticket cannot be mapped to Resource ID."
                            + " The session will not be assigned to any Resource ID.", null);
                }
            } catch (TicketValidationException e) {
                handleError(httpServletResponse, e.getMessage(), e);
            }

        } else {
            // Go further in the filter chain if the session does not contain the authenticated Resource Id or the
            // request does not contain the service ticket.
            chain.doFilter(request, response);
        }

    }

    private String getServiceTicket(final HttpServletRequest request) {
        String queryString = request.getQueryString();
        String ticket = (queryString == null) || !queryString.contains(requestParamNameServiceTicket)
                ? null
                : request.getParameter(requestParamNameServiceTicket);
        if (ticket == null) {
            return null;
        }
        ticket = ticket.trim();
        if (ticket.isEmpty()) {
            return null;
        }
        return ticket;
    }

    private void handleError(final HttpServletResponse httpServletResponse, final String message,
            final TicketValidationException e) throws IOException {
        logService.log(LogService.LOG_ERROR, message, e);
        if (failureUrl != null) {
            httpServletResponse.sendRedirect(failureUrl);
        } else {
            httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
        }
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        // Nothing to do here.
    }

    private String validateServiceTicket(final String serviceTicket) throws IOException, TicketValidationException {

        String validationUrl = String.format(SERVICE_TICKET_VALIDATOR_URL_TEMPLATE,
                casServiceTicketValidatorUrl,
                CasUtil.urlEncode(serviceUrl),
                serviceTicket);
        String response = null;

        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            HttpGet httpGet = new HttpGet(validationUrl);
            HttpResponse httpResponse = httpClient.execute(httpGet);
            HttpEntity responseEntity = httpResponse.getEntity();
            InputStream inputStream = responseEntity.getContent();
            StringWriter writer = new StringWriter();
            IOUtils.copy(inputStream, writer);
            response = writer.toString();
        }

        String error = CasUtil.getTextForElement(response, "authenticationFailure");

        if ((error != null) && !error.trim().isEmpty()) {
            throw new TicketValidationException(error.trim());
        }

        String principal = CasUtil.getTextForElement(response, "user");
        return principal;
    }

}
