var express = require('express');
var fs = require('fs');
var router = express.Router();
const exec = require('child_process').exec;
var chain = require('./chain');
const fetch = require("node-fetch");

var verifiers = new Map();
var port = 5000;
var endpointList = [];

/*
{
    "vidpid": "did:umu:OL-vIdP:test1",
    "policy": ...,
    "vp": ...
}
*/
router.post('/verifypresentation', function(req, res, next) {
    if(verifiers.get(req.body.vidpid)) {
        // verifier is running
        verifytoken(req.body, verifiers.get(req.body.vidpid)).then(response => {
            res.status(200).send({"verification_result": JSON.stringify(response)}); 
        });
    } else {
        // verifier is not running
        // Launch the verifier on port >=5000
        spawnnewverifier();

        // get the vidp from the ledger based on DID
        chain.getvidp(req.body.vidpid).then(vidp => {
            for(var i = 0; i < vidp.did.services.length; i++) {
                endpointList.push("http://"+ vidp.did.services[i].endpoint);
            }
            // add entry map <did, port>
            verifiers.set(req.body.vidpid, port);
            setTimeout(() => {
                setupverifier(endpointList,  verifiers.get(req.body.vidpid)).then(response => {
                    if(response.status < 400) {
                        verifytoken(req.body, verifiers.get(req.body.vidpid)).then(response => {
                            res.status(200).send({"verification_result": JSON.stringify(response)}); 
                        });
                    }
                    port = port + 1;
                });    
            }, 5000);
        });
    }
});

function spawnnewverifier() {
    var childPorcess = exec('java -jar ol-lib/verifier.jar' + " " +  port, function(err, stdout, stderr) {
        if(stdout) {
            console.log(stdout);
        }
        if(stderr) {
            console.log(stderr);
        }
        if (err) { 
            console.log(err);
        }
    });
}

async function setupverifier(endpoints, p) {
    return new Promise(function(resolve, reject) {
        var data = JSON.stringify({urls: endpoints});
        (async () => {
            const rawResponse = await fetch('http://localhost:'+ p + '/verifier/setup', {
              method: 'POST',
              headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
              },
              body: data
            });
            resolve(await rawResponse);
          })();
    });
}

async function verifytoken(request, p) {
    return new Promise(function(resolve, reject) {
        delete request['vidpid'];
        //console.log(JSON.stringify(request));
        fetch('http://localhost:'+ p + '/verifier/verify', {
            method: 'post',
            headers: {
              'Accept': 'application/json, text/plain, */*',
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
          }).then(res => {
              resolve(res.json());
          });
    });
}

module.exports = router;
