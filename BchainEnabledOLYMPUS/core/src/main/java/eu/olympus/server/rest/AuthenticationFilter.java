package eu.olympus.server.rest;

import java.io.IOException;
import java.lang.reflect.AnnotatedElement;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Priority;
import javax.servlet.ServletContext;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import eu.olympus.server.interfaces.PestoIdP;

import javax.ws.rs.Priorities;;

@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthenticationFilter implements ContainerRequestFilter {

	private static final String AUTHENTICATION_SCHEME = "Bearer";
	@Context ServletContext context;
	@Context ResourceInfo resourceInfo;

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		try {
			List<Role> requestedRoles = extractRoles(resourceInfo.getResourceMethod());
			// Handler server-to-server and administrator calls
			String authorizationHeader =
					requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
			String token = 
					authorizationHeader.substring(AUTHENTICATION_SCHEME.length()).trim();
			
			PestoIdP idp = (PestoIdP) context.getAttribute("idp");
			idp.validateSession(token, requestedRoles);
			return;
		} catch (Exception e) {
			abortWithUnauthorized(requestContext);
		}
		abortWithUnauthorized(requestContext);
	}

	private List<Role> extractRoles(AnnotatedElement annotatedElement) {
		Secured secured = annotatedElement.getAnnotation(Secured.class);
		Role[] allowedRoles = secured.value();
		return Arrays.asList(allowedRoles);
	}

	private void abortWithUnauthorized(ContainerRequestContext requestContext) {
		// Abort the filter chain with a 401 status code response
		// The WWW-Authenticate header is sent along with the response
		requestContext.abortWith(
				Response.status(Response.Status.UNAUTHORIZED)
				.header(HttpHeaders.WWW_AUTHENTICATE, 
						AUTHENTICATION_SCHEME)
				.build());
	}
}
