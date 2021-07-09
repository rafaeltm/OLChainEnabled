var express = require('express');
var fs = require('fs');
var router = express.Router();
const { default: fabricNetworkSimple } = require('fabric-network-simple');

var conf = fabricNetworkSimple.config = {
  channelName: "channel",
  contractName: "OlympusManager",
  connectionProfile: {
    name: "umu.fabric",
    version: "1.0.0",
    channels : {
      channel : {
        orderers : [ "orderer.example.com" ],
        peers : {
          "peer0.org1.example.com" : {
            endorsingPeer : true,
            chaincodeQuery : true,
            ledgerQuery : true,
            eventSource : true,
            discover : true
          }
        }
      },
    },
    organizations : {
      Org1 : {
        mspid : "Org1MSP",
        peers : [ "peer0.org1.example.com"],
        certificateAuthorities : [ "ca.org1.example.com" ]
      }
    },
    orderers : {
      "orderer.example.com" : {
        url : "grpcs://orderer.example.com:7050",
        tlsCACerts: {
          path:
            "D:\\ProyectosUMU\\SignAPI\\test\\ordererOrganizations\\example.com\\orderers\\orderer.example.com\\msp\\tlscacerts\\tlsca.example.com-cert.pem",
        },
      }
    },
    peers : {
      "peer0.org1.example.com" : {
        "url" : "grpcs://peer0.org1.example.com:7051",
        tlsCACerts: {
          path:
            "D:\\ProyectosUMU\\SignAPI\\test\\peerOrganizations\\org1.example.com\\peers\\peer0.org1.example.com\\msp\\tlscacerts\\tlsca.org1.example.com-cert.pem",
        },
      },
    },
  },
  certificateAuthorities : {
      "ca.org2.example.com" : {
        "url" : "https://ca.org2.example.com:8054"
      },
      "ca.org1.example.com" : {
        "url" : "https://ca.org1.example.com:7054",
        "httpOptions" : {
          "verify" : false
        },
        "registrar" : [ {
          "enrollId" : "admin",
          "enrollSecret" : "adminpw"
        } ]
      }
  },
  identity: {
    mspid: 'Org1MSP',
    certificate: '-----BEGIN CERTIFICATE-----\nMIICODCCAd+gAwIBAgIUKBUPwZRyw2/gB6g5mH2Ycm98FYEwCgYIKoZIzj0EAwIw\nczELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh\nbiBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT\nE2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMjEwNDIwMDk1NjAwWhcNMjIwNDIwMTAw\nMTAwWjAhMQ8wDQYDVQQLEwZjbGllbnQxDjAMBgNVBAMTBWFkbWluMFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAEXzuVlwX44yrMOU6lHucmv8eb2m/l5qo9L53P4oxo\nN4VREUxwt+bkSGa/fdOYWGuAf3180KfyC4yyBlfgD8997qOBojCBnzAOBgNVHQ8B\nAf8EBAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB\n/wQCMAAwHQYDVR0OBBYEFDQeuDNyzpIvLH2YOcxywjjYkYKfMCsGA1UdIwQkMCKA\nINnBdJS4vqiePq72BPyRBhfjPugrXxUdw7LGuWc5UTw8MBQGA1UdEQQNMAuCCWxv\nY2FsaG9zdDAKBggqhkjOPQQDAgNHADBEAiBqWYubGtltyKf/ISvtG/bqH8dO61VP\nzEf2d9Mj8yhCHwIgB/O1CXpIj5ZvQlQxsLADp1TypOqavgF9H3v5m1PpptA=\n-----END CERTIFICATE-----\n',
    privateKey: '-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgjHuhQK+30KcXicM/\nZ59Wyh92nl8+vu1lTs+Nrw9o3oigCgYIKoZIzj0DAQehRANCAARfO5WXBfjjKsw5\nTqUe5ya/x5vab+Xmqj0vnc/ijGg3hVERTHC35uRIZr9905hYa4B/fXzQp/ILjLIG\nV+APz33u\n-----END PRIVATE KEY-----\n',
  },
  settings: {
    enableDiscovery: true,
    asLocalhost: false,
  }
}

asyncCall();
var fabconnection;

function initConection() {
  return new Promise(resolve => {
    fabconnection = new fabricNetworkSimple(conf);
  });
}
  
async function asyncCall() {
  console.log('Init fabric connection');
  await initConection();
}

router.get('/', function(req, res, next) {
    res.status(200).send("This is the ledger endpoint POST \n Endpoints: \n getvidp \n getschema \n getservices \n getservice");
});

router.post('/getpartialidp', function(req, res, next) {
  var idpartial = req.body.idpartial;
  fabconnection.queryChaincode("getpartialidp", [idpartial]).then(queryChaincodeResponse => {
    res.status(200).send(queryChaincodeResponse.queryResult);
  }).catch ( error => {
    console.log(error);
    res.status(404).send(error);
  });
});

async function getvidp(vidpid) {
  return new Promise(function(resolve, reject){ 
    fabconnection.queryChaincode('getvirtualidp',[vidpid]).then(queryChaincodeResponse => {
      resolve(JSON.parse(queryChaincodeResponse.queryResult[0]));
    }).catch ( error => {
      reject(error);
    });
  });
};

router.post('/getvidp/', function(req, res, next) {
  var vidpid = req.body.vidpid;
  getvidp(vidpid).then(vidp => {
    res.status(200).send(vidp);
  }).catch(error => {
    console.log(error);
    res.status(500).send();
  });
});

router.get('/getvidp', function(req, res, next) {
  var activeFlag = req.query.active;
  fabconnection.queryChaincode('getvirtualidp',[""]).then(queryChaincodeResponse => {
    var responseObject = [];
    for(var i = 0; i < queryChaincodeResponse.queryResult.length; i++) {
      if(activeFlag && activeFlag != 0) {
        if(JSON.parse(queryChaincodeResponse.queryResult[i]).status == "ACTIVE") {
          responseObject.push(JSON.parse(queryChaincodeResponse.queryResult[i]));
        }
      } else {
        responseObject.push(JSON.parse(queryChaincodeResponse.queryResult[i]));
      }
    }
    res.status(200).send(responseObject);
  }).catch ( error => {
    console.log(error);
    res.status(404).send(error);
  });
});

router.post('/getschema', function(req, res, next) {
  let partialidp = req.body.partialidpid;
  fabconnection.queryChaincode('getschema', [partialidp]).then(queryChaincodeResponse => {
    var responseObject = queryChaincodeResponse.queryResult;
    responseObject.schema = JSON.parse(queryChaincodeResponse.queryResult.schema);
    
    res.status(200).send(responseObject);
  }).catch ( error => {
    console.log(error);
    res.status(404).send(error);
  });
});

router.get('/getservices', function(req, res, next) {
  var activeFlag = req.query.active;
  fabconnection.queryChaincode('getservice', [""]).then(queryChaincodeResponse => {
    var responseObject = [];
    for(var i = 0; i < queryChaincodeResponse.queryResult.length; i++) {
      if(activeFlag && activeFlag != 0) {
        if(JSON.parse(queryChaincodeResponse.queryResult[i]).status == "ACTIVE") {
          responseObject.push(JSON.parse(queryChaincodeResponse.queryResult[i]));
        }
      } else {
        responseObject.push(JSON.parse(queryChaincodeResponse.queryResult[i]));
      }
    }
    res.status(200).send(responseObject);
  }).catch ( error => {
    console.log(error);
    res.status(404).send(error);
  });
});

router.post('/getservice', function(req, res, next) {
  let serviceid = req.body.serviceid;
  fabconnection.queryChaincode('getservice', [serviceid]).then(queryChaincodeResponse => {
    var resObj = JSON.parse(queryChaincodeResponse.queryResult);
    var preds = JSON.parse(resObj.predicates);
    resObj.predicates = preds;
    res.status(200).send(resObj);
  }).catch ( error => {
    console.log(error);
    res.status(404).send(error);
  });
});

/**
 * Example:
 * {
    "did": {
      "service": {
        "serviceEndpoint": "testdomain2.com",
        "type": "web service"
      },
      "context": "some context",
      "id": "testdomain2"
    },
    "domain": "testdomain2.com",
    "predicates": [
        {
            "attributeName":"url:Organization","operation":"REVEAL","value":null,"extraValue":null
        },
        {
            "attributeName":"url:DateOfBirth","operation":"INRANGE","value":"Tue Jan 05 01: 00: 00 CET 1988","extraValue":"Wed Jan 05 01: 00: 00 CET 2000"
        },
        {
            "attributeName":"url:Role","operation":"REVEAL","value":null,"extraValue":null
        },
        {
            "attributeName":"url:Mail","operation":"REVEAL","value":null,"extraValue":null
        },
        {
            "attributeName":"url:AnnualSalary","operation":"INRANGE","value":20000,"extraValue":40000
        }
    ]
  }
 */
router.post('/addservice', function(req, res, next) {
  let servicedid = req.body.did;
  let domain = req.body.domain;
  let predicates = req.body.predicates;
  fabconnection.invokeChaincode('addservice', [JSON.stringify(servicedid), domain, JSON.stringify(predicates)], {}).then(invokeResult => {
    res.status(201).send(invokeResult);
  }).catch ( error => {
    console.log(error);
    res.status(404).send(error);
  });
});

router.get('/getevents', function(req, res, next) {
  fabconnection.queryChaincode('getevent', [""]).then(queryChaincodeResponse => {
    var responseObject = [];
    for(var i = 0; i < queryChaincodeResponse.queryResult.length; i++) {
      responseObject.push(JSON.parse(queryChaincodeResponse.queryResult[i]));
    }
    res.status(200).send(responseObject);
  }).catch ( error => {
    console.log(error);
    res.status(404).send(error);
  });
});

/**
{
    "eventname": "new event",
    "eventtype": "INFORMATION",
    "eventdata": "whatever"
}
{
    "eventname": "new event",
    "eventtype": "POLICY",
    "eventdata": "whatever"
}
{
    "eventname": "new event",
    "eventtype": "REPORT",
    "eventdata": "whatever"
}
 */
router.post('/sendevent', function(req, res, next) {
  let body = req.body.eventdata;
  let type = req.body.eventtype;
  let title = req.body.eventname;
 fabconnection.invokeChaincode('addevent', [title, type, body], {} ).then(invokeResult => {
    res.status(201).send();
  }).catch ( error => {
    console.log(error);
    res.status(404).send(error);
  });
});


module.exports = {
  router: router,
  getvidp: getvidp
}

