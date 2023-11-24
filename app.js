require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();
const secretKey ='hjhfieideiieieueieiuediweuiddeki';

app.use(express.json());

// Logic goes here

module.exports = app;

const User = require("./model/user");
// ...
const authenticateToken = (req, res, next) => {
  let token = req.headers['authorization'];
  token = token.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    console.log(token)
    if (err) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    req.user = user;
    next();
  });
};
// function for hashpassword
async function hashpassword(password){
  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);
  return hashedPassword;
}

app.post('/register', async (req, res) => {
  try {
    const { first_name,
      last_name,
      email, 
      password } = req.body;

    // Hash the password before storing it in the database
    // Hash the password
    const hashedPassword =await hashpassword(password);

    const user = new User({
      first_name,
      last_name,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password:hashedPassword,
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// compare password function
async function comparePasswords(plaintextPassword, hashpassword) {

  // console.log('hashpassword',plaintextPassword,hashpassword);
    const match = await bcrypt.compare(plaintextPassword, hashpassword);
    // console.log("match",match);
    return match;
}

// Express route to login a user
app.post('/login', async (req, res) => {
  try {
    const { first_name,last_name,email, password } = req.body;
// console.log("password",password,email)

    // Find the user in the database
    const user = await User.findOne({ email:email });

    // If the user doesn't exist or the passwords don't match, send an error response
    if (!user || !(await comparePasswords(password, user.password))) {
      return res.status(401).send('Invalid credentials');
    }

    const token = jwt.sign({ first_name }, secretKey, { expiresIn: '1h' });
    res.json({ token });
    console.log("login successfully");

    
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});



