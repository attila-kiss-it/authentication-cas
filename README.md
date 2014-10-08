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
 configuration) is recommended for security reasons. For e.g. 
 "https://cas.example.com/cas/serviceValidate".
 (cas.service.ticket.validation.url)
 - **Failure URL**: The URL where the user will be redirected in case of 
 failed request processing. For e.g. "/failed.html", the user will be 
 redirected to "http://app.example.com/failed.html" (failure.url)
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
// sessionAuthenticationFilter and sessionLogoutServlet are provided by the 
// authentication-http-session component, casAuthenticationFilter and 
// casAuthenticationEventListener are provided by this authentication-cas 
// component.

// The sessionAuthenticationFilter is responsible to check the HTTP session 
// for an Authenticated Resource ID and execute the authenticated process in 
// the name of it if available.
Filter sessionAuthenticationFilter = ...

// The sessionLogoutServlet is responsible to invalidate the HTTP session
// of the current user.
Servlet sessionLogoutServlet = ...

// The casAuthenticationFilter handles the CAS service ticket validation and 
// CAS logout request processing.
Filter casAuthenticationFilter = ...

// The casAuthenticationEventListener ensures the operation of the component.
// This EventListener must be registered exactly twice in case of Jetty:
//  - to the ServletContextHandler
//  - to the HashSessionManager
EventListener casAuthenticationEventListener = ...
```

Initialize the Jetty Web Server on port 8080:

```java
Server server = new Server(8080);
```

Initialize a *ServletContextHandler* the handles the registered *Filters*, 
*Servlets* and *EnventListeners*:

```java
// Instantiate a ServletContextHandler that support HTTP sessions.
ServletContextHandler servletContextHandler = 
	new ServletContextHandler(ServletContextHandler.SESSIONS);

// The order of the filter registration is important.

// Register the sessionAuthenticationFilter with URL pattern "/*".
servletContextHandler.addFilter(
	new FilterHolder(sessionAuthenticationFilter), "/*", null);

// Register the casAuthenticationFilter with URL pattern "/*".
servletContextHandler.addFilter(
	new FilterHolder(casAuthenticationFilter), "/*", null);

// Register the sessionLogoutServlet with URL path "/logout".
servletContextHandler.addServlet(
	new ServletHolder("sessionLogoutServlet", sessionLogoutServlet), "/logout");

// Register the casAuthenticationEventListener to the ServletContextHandler. 
// The CasAuthenticationComponent implements the ServletContextListener 
// interface, this will be registered in this case.
servletContextHandler.addEventListener(
	casAuthenticationEventListener);

// Register the ServletContextHandler to the Server.
server.setHandler(servletContextHandler);
```

Initialize a persistent session manager:

```java
HashSessionManager sessionManager = new HashSessionManager();

// Store the sessions in a file system.
sessionManager.setStoreDirectory(
	new File("/the/jetty/sessions/will/be/stored/here/"));

// !!!-IMPORTANT-!!! Lazy load is required to initialize the servlet context 
// before restoring the sessions.
sessionManager.setLazyLoad(true);

// Register the EventListener to the session manager.
sessionManager.addEventListener(casAuthenticationEventListener);

// Register the session manager to the session handler.
SessionHandler sessionHandler = servletContextHandler.getSessionHandler();
sessionHandler.setSessionManager(sessionManager);
```

Start (and optionally join) the Jetty Web Server:

```java
server.start();

// Optionally to have the current thread wait until the server is running.
server.join();
```

Finally we have a Jetty Web Server with persistent session management 
integrated to a CAS server that handles authentication. Some important notes: 
 - The server will accept and the filters will check all the requests that 
 match the "/*" pattern.
 - Redirecting the user to the CAS login page (with a service URL, for e.g. 
 "https://cas.example.com/cas/login?service=http%3A%2F%2Fapp.example.com%2F", 
 note that the URL in the service parameter is URL encoded) - if 
 authentication is required - is the responsibility of the application, not 
 covered by this example either the component.
 - Any service URL (The URL which identifies the service in the CAS server and 
 the user will be redirected to this page after a successful CAS login. GET 
 parameters in the URL is also supported) will be accepted because the 
 *casAuthenticationFilter* listens on patter "/*". The filter will validate 
 the service ticket provided by the CAS server and will invalidate the session 
 of the user if a logout request is sent by the CAS server.
 - Invoking the *sessionLogoutServlet* on URL "http://app.example.com/logout" 
 will invalidate the session of the user managed by the session manager 
 registered to Jetty Web Server. The user remains logged in to CAS. If a new 
 request is sent to the Jetty Web Server, a new session will be created and 
 assigned to the same user because of a CAS cookie still exists and valid. 
 It is the responsibility of the application to *Single Logout (SLO)* the user 
 (if required) by invoking the CAS logout URL (for e.g. 
 "https://cas.example.com/cas/logout") on the CAS server. Invoking CAS logout 
 also invalidates the session of the user because the 
 *casAuthenticationFilter* processes the logout request sent by the CAS 
 server (back channel communication).

A complex example can be found under the integration tests project in the 
*org.everit.osgi.authentication.cas.tests.CasAuthenticationTestComponent* 
class.

#Useful CAS links
 - [CAS 4.0.0 home page][3]
 - [CAS flow diagram][4]
 - [Logout and Single Logout (SLO)][5]

#Concept
Full authentication concept is available on blog post 
[Everit Authentication][1].

[1]: http://everitorg.wordpress.com/2014/07/31/everit-authentication/
[2]: https://github.com/everit-org/authentication-http-session
[3]: http://jasig.github.io/cas/4.0.0/index.html
[4]: http://jasig.github.io/cas/4.0.0/images/cas_flow_diagram.png
[5]: http://jasig.github.io/cas/4.0.0/installation/Logout-Single-Signout.html
