const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const jwt = require('jsonwebtoken')
const { timeout } = require("./utils")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/user-info', (req, res) => {
	if(!req.headers.authorization) {
		res.status(401).end();
		return;
	}
	const token = req.headers.authorization.slice('Bearer'.length+1);
	let payload;
	try{
		payload = jwt.verify(token, config.publicKey, {
			algorithms: ['RS256']
		});
	}catch(e){
		res.status(401).end();
		return
	}
	const { userName, scope } = payload;
	const user = users[userName];
	let permisssions = scope.split(' ');
	permisssions = permisssions.map(permission => permission.slice('permission:'.length));
	const userIfo = permisssions.reduce((acc, value) => {
		return {
			...acc,
			[value]: user[value]
		}
	}, {});
	res.status(200).json(userIfo);
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
