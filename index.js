require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

app.use(express.static(__dirname + "/public"));

const expireTime = 60 * 60 * 1000; // expires after 1 hour (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {
    if (!req.session.username){
    res.send(`
      <div>
        <button onclick="window.location.href='/signup'">Sign up</button><br>
        <button onclick="window.location.href='/login'">Log in</button>
      </div>
    `);
    return;
    } 
    var username = req.session.username;
    res.send(`
    <div>
    Hello, ${username}!<br>
    <button onclick="window.location.href='/members'">Go to Members Area</button>
    <br>
    <button onclick="window.location.href='/logout'">Log out</button>
    </div>
    `);
  });
  

  app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post' >
        <input name='email' type='email' placeholder='email'><br>
        <input name='password' type='password' placeholder='password'><br>
        <button>Submit</button><br>
    </form>
    `;
    res.send(html);
});


app.get('/signup', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='name'><br>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!username) {
        return res.status(400).send('Name is required. <br><br><a href="/signup">Try again</a>');
    }

    if (!email) {
        return res.status(400).send('Email is required. <br><br><a href="/signup">Try again</a>');
    }

    if (!password) {
        return res.status(400).send('Password is required. <br><br><a href="/signup">Try again</a>');
    }

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/signup");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username, email, password: hashedPassword});
	console.log("Inserted user");
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
    return;
});

app.get ('/members', (req, res) => {
    if (!req.session.username){
        res.redirect('/');
        return;
    }
    var username = req.session.username;

    var random = Math.floor(Math.random() * 3) + 1;
    res.send(`
    <div style="display: block;">
    <h1>Hello ${username}</h1>
    <img src='/milkmocha${random}.jpg' style="display: block;"/>
    <button style="display: block;" onclick="window.location.href='/logout'">Sign out</button>
    </div>
    `);
})

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;
    
	const schema = Joi.object(
		{
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
    const validationResult = schema.validate({email, password});

	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   return;
	}

	const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
    
	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		return;
	}
    
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.username = result[0].username;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;
        console.log("username: "+ req.session.username);
		res.redirect('/members');
		return;
	} else {
        console.log("incorrect password");
        res.send("Invalid email/password combination.<br><br><a href=\"/login\">Try again</a>");
        return;
    }
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 


