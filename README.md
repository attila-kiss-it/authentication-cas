authentication-cas
==================

Authentication mechanism implemented based on [Everit Authentication][1] in 
case of using CAS. It is recommended to use this component in combination with
[authentication-http-session][2] component, check the **Usage** section for 
more details and check check the javadoc of the 
*org.everit.osgi.authentication.cas.internal* package.

#Component
The module contains one Declarative Services component. The component can be 
instantiated multiple times via Configuration Admin. The component registers 
two OSGi services:
 - **javax.servlet.Filter**: Handles the CAS service ticket validation and CAS 
 logout request processing.
 - **java.util.EventListener**: As a **ServletContextListener**, a 
 **HttpSessionListener** and a **HttpSessionAttributeListener** to handle 
 ServletContext, HttpSession and HttpSession attribute related events that 
 ensures the operation of the component. For more information check the 
 javadoc of the *org.everit.osgi.authentication.cas.internal* package.

#Configuration
 - **Service Description**: The description of this component configuration. 
 It is used to easily identify the services registered by this component. 
 (service.description)
 - **CAS service ticket validation URL**: The URL provided by the CAS server 
 for service ticket validation. HTTPS protocol (and java keystore 
 configuration) is recommended for security reasons. 
 (cas.service.ticket.validation.url)
 - **Failure URL**: The URL where the user will be redirected in case of 
 failed request processing. (failure.url)
 - **AuthenticationSessionAttributeNames OSGi filter**: OSGi Service filter 
 expression for AuthenticationSessionAttributeNames instance. 
 (authenticationSessionAttributeNames.target)
 - **ResourceIdResolver OSGi filter**: OSGi Service filter expression for 
 ResourceIdResolver instance. (resourceIdResolver.target)
 - **SAXParserFactory OSGi filter**: OSGi Service filter expression for 
 SAXParserFactory instance. (saxParserFactory.target)
 - **LogService OSGi filter**: OSGi Service filter expression for LogService 
 instance. (logService.target)

#Usage
This usage example demonstrates how to use this component with Jetty Web 
Server.

Get the services of the following interfaces in the way you like:

```java
/* sessionAuthenticationFilter and sessionLogoutServlet are provided by the 
authentication-http-session component, casAuthenticationFilter and 
casAuthenticationEventListener are provided by this authentication-cas 
component */

// The sessionAuthenticationFilter is responsible to check the HTTP session
Filter sessionAuthenticationFilter = ... 
Servlet sessionLogoutServlet = ...

Filter casAuthenticationFilter = ...
EventListener casAuthenticationEventListener = ...
```

Initialize the Jetty Web Server on port 8080:

```java
Server server = new Server(8080);
```

Initialize a *ServletContextHandler* the handles the registered *Filters*, 
*Servlets* and *EnventListeners*:

```java
ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);

servletContextHandler.addFilter(
	new FilterHolder(sessionAuthenticationFilter), "/*", null);
servletContextHandler.addFilter(
	new FilterHolder(casAuthenticationFilter), "/*", null);
servletContextHandler.addServlet(
	new ServletHolder("sessionLogoutServlet", sessionLogoutServlet), "/logout");

servletContextHandler.addEventListener(
	casAuthenticationEventListener);

server.setHandler(servletContextHandler);
```

Initialize a persistent session manager:

```java
HashSessionManager sessionManager = new HashSessionManager();

sessionManager.setStoreDirectory(new File("/the/jetty/sessions/will/be/stored/here/"));
sessionManager.setIdleSavePeriod(1);
sessionManager.setSavePeriod(1);
sessionManager.setLazyLoad(true); // required to initialize the servlet context before restoring the sessions
sessionManager.addEventListener(casAuthenticationEventListener);

SessionHandler sessionHandler = servletContextHandler.getSessionHandler();
sessionHandler.setSessionManager(sessionManager);
```

Start the Jetty Web Server:

```java
server.start();
```

A full usage example can be found under the integration tests project in the 
*org.everit.osgi.authentication.cas.tests.CasAuthenticationTestComponent* 
class.

#Concept
Full authentication concept is available on blog post 
[Everit Authentication][1].

[1]: http://everitorg.wordpress.com/2014/07/31/everit-authentication/
[2]: https://github.com/everit-org/authentication-http-session
