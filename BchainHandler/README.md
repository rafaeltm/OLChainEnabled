## RUN
npm install

DEBUG=signapi:* npm start

## PATCH LIBRARY FABRIC NETWORK SIMPLE
Edit the index.js inside node_modules queryChaincode and invokeChaincode to return errors instead of console.log()
Edit the index.js inside node_modules queryChaincode and invokeChaincode to return JSON instead of Strings.
result = JSON.parse((queryResult));
result = JSON.parse((invokeResult));

## Cert tool
https://certificatetools.com/

## Cert creation
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

## Operations

GET http://localhost:3000/sign  -- Information about how to sign something

POST http://localhost:3000/sign  -- Signs the data sent in body <br>
content-type: application/json<br>
body: "data": {a: b, c: d ...}<br>
Response: Base64 signature<br>

POST http://localhost:3000/sign/verify  -- Checks the signature<br>
content-type: application/json<br>
body: data (the original data) and signature (base64 obtained from the sign method)<br>
response: signature_status<br>

POST http://localhost:3000/sign/university|financial|grocery  -- returns a signed set of attributes <br>
content-type: application/json<br>
body: user and password (test, test)<br>
response: signature and data<br>