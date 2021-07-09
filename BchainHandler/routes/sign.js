var express = require('express');
var crypto = require('crypto');
var fs = require('fs');
var router = express.Router();

/*const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
	// The standard secure default length for RSA keys is 2048 bits
	modulusLength: 2048,
})
*/
const privateKey = fs.readFileSync('Keys\\key.pem')
const pubKeyObject = crypto.createPublicKey({
  key: privateKey,
  format: 'pem'
})
const publicKey = pubKeyObject.export({
  format: 'pem',
  type: 'spki'
})

const credential = {
  "user": "test",
  "password": "test"
};

const bchainAttrs = {
  "url:Organization": "UMU",
  "url:DateOfBirth": "1989-01-05T00:00:00",
  "url:Mail": "mail@um.es",
  "url:Role": "student",
  "url:AnnualSalary": 35000
};

const universityAttributes = {
  "organization": "Fake University",
  "age": 24,
  "mail": "mail@organization.com",
  "role": "Student"
};

const bankingAttributes = {
  "debts": false,
  "balance": 25000,
  "client_type": "Standard"
};

const groceryAttributes = {
  "since": "2018-11-04T16:39:00+0000", // ISO 8601
  "fidelity_points": 536,
  "phone": "+34 600 10 11 12"
};


/* Usage*/
router.get('/', function(req, res, next) {
  res.send('POST with Data to sign');
});

router.post('/', function(req, res, next) {
  const signature = crypto.sign("sha256", Buffer.from(JSON.stringify(req.body.data)), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
  const aux = {
    'signature': signature.toString("base64"),
    'data': req.body.data
  };
  console.log(aux);
  res.status(200).send(aux);
});

router.post('/verify', function(req, res, next) {
  const isVerified = crypto.verify("sha256", Buffer.from(JSON.stringify(req.body.data)),{
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    }, Buffer.from(req.body.signature, 'base64'))
  
  // isVerified should be `true` if the signature is valid
  console.log("RESULT: " + isVerified);
  res.status(200).send({
    'signature_status': isVerified
  });
});

router.get('/bchainattrs', function(req, res, next) {
    const signature = crypto.sign("sha256", Buffer.from(JSON.stringify(bchainAttrs)), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    });
    res.status(200).send({
      'signature': signature.toString("base64"),
      'data': bchainAttrs
    });
});

router.post('/university', function(req, res, next) {
  if ((req.body.user === credential.user) && (req.body.password === credential.password)) {
    const signature = crypto.sign("sha256", Buffer.from(JSON.stringify(universityAttributes)), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    });
    res.status(200).send({
      'signature': signature.toString("base64"),
      'data': universityAttributes
    });
  } else {
    res.status(401).send("Invalid credentials");
  }
});

router.post('/financial', function(req, res, next) {
  if ((req.body.user === credential.user) && (req.body.password === credential.password)) {
    const signature = crypto.sign("sha256", Buffer.from(JSON.stringify(bankingAttributes)), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    });
    res.status(200).send({
      'signature': signature.toString("base64"),
      'data': bankingAttributes
    });
  } else {
    res.status(401).send("Invalid credentials");
  }
});

router.post('/grocery', function(req, res, next) {
  if ((req.body.user === credential.user) && (req.body.password === credential.password)) {
    const signature = crypto.sign("sha256", Buffer.from(JSON.stringify(groceryAttributes)), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    });
    res.status(200).send({
      'signature': signature.toString("base64"),
      'data': groceryAttributes
    });
  } else {
    res.status(401).send("Invalid credentials");
  }
});

module.exports = router;
