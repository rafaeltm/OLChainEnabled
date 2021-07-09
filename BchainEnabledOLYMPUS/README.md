To build the project, use the commands:
>mvn clean
>mvn install

*Note that the 'mvn clean' command is needed to install the MIRACL jar dependency into the local m2 repository in order to build the project.

A sample vIdP may be run from the the cfp-usecase sub-project using the command:

>java -jar CFP-IdP-jar-with-dependencies.jar <configuration file>

ie. to use the sample vIdP setup, open 3 terminals and start the 3 partial IdPs:

cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup0.json
cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup1.json
cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup2.json

This will start demonstrators using ports 9080-9082(plain HTTP) and 9933-9935(TLS)

In order to initiate the intra-server key refresh protocol, an administrator may make a HTTP POST request to /idp/startRefresh on one of the partial IdPs.
This can be done using any HTTP client, eg. curl: 
'curl -s -X POST -H "Authorization: Bearer <token>" <url>'

In order to start the refresh protocol using the setup in the cfp-usecase project, the following command would be used: 
'curl.exe -s -X POST -H "Authorization: Bearer 8Y9mocwbGZbU0YSNQR46kb6DHYuniHqpXmOjM2uUQ+iEmlX/ka4ZPzBjgrWz9Zw/zeNA4Neq9LSLAaPa6+B0Vg==" http://localhost:9080/idp/startRefresh'