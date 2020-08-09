const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const url = require('url')
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/authorize', (req, res) => {
	const clientID = req.query.client_id;
	const client = clients[clientID];

	if (!client) {
		res.status(401).end()
		return
	}
	if (!containsAll(client.scopes, req.query.scope.split(" "))) {
		res.status(401).end()
		return
	}
	const requestId = randomString();
	requests[requestId] = req.query;

	res.render('login', {
		client,
		scope: req.query.scope,
		requestId
	});
});

app.post('/approve', (req, res) => {
	const { userName, password, requestId } = req.body;

	if(users[userName] !== password) {
		res.status(401).end();
		return;
	}
	if(!requests[requestId]) {
		res.status(401).end();
		return;
	}
	const clientReq = requests[requestId];
	delete requests[requestId];
	const rs = randomString();
	authorizationCodes[rs] = {
		clientReq,
		userName
	};
	const redirectUri = url.parse(clientReq.redirect_uri);
	redirectUri.query = {
		code: rs,
		state: clientReq.state
	};
	res.redirect(url.format(redirectUri));
});

app.post('/token', (req, res) => {
	const auth = req.headers.authorization;
	if(!auth) {
		res.status(401).end();
		return;
	}
	const authCredentials = decodeAuthCredentials(auth);
	const clientId = Object.keys(clients).find(item => item === authCredentials.clientId);
	if(!clientId) {
		res.status(401).end();
		return;
	}
	if(clients[clientId].clientSecret !== authCredentials.clientSecret){
		res.status(401).end();
		return;
	}
	if(!authorizationCodes[req.body.code]){
		res.status(401).end();
		return;
	}
	const obj = authorizationCodes[req.body.code];
	delete authorizationCodes[req.body.code];
	
	const token = jwt.sign(
		{
			userName: obj.userName,
			scope: obj.clientReq.scope 
		},
		config.privateKey,
		{
			'algorithm': 'RS256'
		}
	);
	res.status(200).json(
		{
			token_type:'Bearer',
			access_token: token
		}
	);
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
