const express = require('express');
var path = require('path');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
const cors = require('cors');
const {
  decryptSgIdData,
  decryptSingpassData,
  createHeaders,
  getProfileAndScope
} = require('./lib/utils');
require('dotenv').config();
const {
  MYINFO_AUTHORISE_URL,
  MYINFO_TOKEN_URL,
  MYINFO_PERSON_URL,
  MYINFO_CLIENT_ID,
  MYINFO_CLIENT_SECRET,
  MYINFO_ATTRIBUTES,
  MYINFO_PURPOSE,
  SGID_AUTHORISE_URL,
  SGID_SCOPE,
  SGID_TOKEN_URL,
  SGID_PERSON_URL,
} = process.env;


const app = express();
const port = 3001;


app.use(express.json());
app.use(cors());


app.set('views', path.join(__dirname, 'public/views'));
app.set('view engine', 'pug');

app.use(express.static('public'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: false
}));
app.use(cookieParser());

app.get('/', function (req, res) {
  res.sendFile(__dirname + '/public/index.html');
});


// callback function - directs back to home page
app.get('/callback', function (req, res) {
  res.sendFile(__dirname + '/public/index.html');
});

app.get('/getEnv', function (req, res) {
  res.status(200).send({
    "myinfo_authorise_url": MYINFO_AUTHORISE_URL,
    "myinfo_client_id": MYINFO_CLIENT_ID,
    "myinfo_attributes": MYINFO_ATTRIBUTES,
    "myinfo_purpose": MYINFO_PURPOSE,
    "sgid_authorise_url": SGID_AUTHORISE_URL,
    "sgid_scope": SGID_SCOPE
  });
})

app.post('/getSingpassData', async function (req, res) {
  try {
    const auth_code = req.body.auth_code;
    const redirect_uri = req.body.redirect_uri;
    const token_url_headers = createHeaders("POST", {
      "code": auth_code,
      "redirect_uri": redirect_uri,
      "client_secret": MYINFO_CLIENT_SECRET
    }, MYINFO_TOKEN_URL, MYINFO_CLIENT_ID)
    // get token
    const token_response = await fetch(MYINFO_TOKEN_URL, {
      method: "POST",
      headers: token_url_headers,
      body: new URLSearchParams({ code : auth_code})
    })
    const token_data = await token_response.json();
    const token = token_data.access_token;
    const { uinfin, attributes } = getProfileAndScope(token)

    // get person data
    const person_url = `${MYINFO_PERSON_URL}/${uinfin}`
    const person_url_headers = createHeaders("GET", {
      "attributes": attributes
    }, person_url, MYINFO_CLIENT_ID, token)
  
    const person_response = await fetch(`${MYINFO_PERSON_URL}/${uinfin}?attributes=${attributes}`, {
      method: "GET",
      headers: person_url_headers
    })


    const person_response_body = await person_response.text();
    const decrypted_person_data = await decryptSingpassData(person_response_body);
    res.status(200).send(decrypted_person_data);
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      "error": error
    });
  }
})

app.post('/getSgIDData', async function (req, res) {
  try {
    const auth_code = req.body.code;
    const token_response = await fetch(SGID_TOKEN_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ code : auth_code, clientId: 'sgidclient'})
    })
    const token_data = await token_response.json();

    const person_response = await fetch(SGID_PERSON_URL, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token_data.access_token}`
      }
    })
    
    const person_response_body = await person_response.json();
    const data = await decryptSgIdData(person_response_body);
    res.status(200).send(data)
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      "error": error
    });
  }
})

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers
// print stacktrace on error
app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: err
  });
});



app.listen(port,'::', () => console.log(`Demo App Client listening on port ${port}!`));