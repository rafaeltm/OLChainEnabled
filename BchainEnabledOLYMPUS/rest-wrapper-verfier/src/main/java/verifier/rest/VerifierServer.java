package verifier.rest;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.verifier.W3CPresentationVerifierOL;
import eu.olympus.verifier.interfaces.OLVerificationLibrary;
import eu.olympus.verifier.interfaces.W3CPresentationVerifier;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public class VerifierServer {
    private Server server;

    private static VerifierServer myself = null;

    private W3CPresentationVerifier verifier;

    private VerifierServer(){
    }


    public W3CPresentationVerifier getVerifier() {
        return verifier;
    }

    public void setVerifier(W3CPresentationVerifier verifier) {
        this.verifier = verifier;
    }

    public static VerifierServer getInstance(){
        if(myself == null) {
            myself = new VerifierServer();
            return myself;
        } else {
            return myself;
        }
    }

    public void start(int port, int tlsPort, String certPath, String ksPassword, String kmPassword) throws Exception{
        System.out.println("STARTING REST Verifier:" +port);
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        if(verifier!=null)  // If manual setup was performed, e.g. for testing
            context.setAttribute("verifier", verifier);

        server = new Server();
        ServerConnector connector = new ServerConnector(server);

        connector.setPort(port);
        Connector[] connectors = new Connector[1];
        connectors[0] = connector;
        if(certPath != null){
            connectors = new Connector[2];
            connectors[0] = connector;
            HttpConfiguration https = new HttpConfiguration();

            https.addCustomizer(new SecureRequestCustomizer());

            SslContextFactory sslContextFactory = new SslContextFactory();

            sslContextFactory.setKeyStorePath(certPath);

            sslContextFactory.setKeyStorePassword(ksPassword);

            sslContextFactory.setKeyManagerPassword(kmPassword);

            ServerConnector sslConnector = new ServerConnector(server,
                    new SslConnectionFactory(sslContextFactory, "http/1.1"),
                    new HttpConnectionFactory(https));

            sslConnector.setPort(tlsPort);
            connectors[1] = sslConnector;
        }

        server.setConnectors(connectors);

        server.setHandler(context);

        ServletHolder jerseyServlet = context.addServlet(
                org.glassfish.jersey.servlet.ServletContainer.class, "/*");
        jerseyServlet.setInitOrder(0);

        // Tells the Jersey Servlet which REST service/class to load.

        jerseyServlet.setInitParameter(
                "jersey.config.server.provider.classnames",
                VerifierServlet.class.getCanonicalName());

        server.start();
    }

    public void stop() throws Exception{
        System.out.println("STOPPING REST Verifier");
        server.stop();
    }
}
