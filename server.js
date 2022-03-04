const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const morgan = require('morgan');
const app = express();
const SERVER_PORT = process.env.SERVER_PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'jwtsecret';

const { verifyBearerTokenMiddleware } = require('./src/middlewares');

async function findUserByEmail(email = null) {
  return new Promise((resolve, reject) => {
    if (email !== 'r.ludosanu@gmail.com') {
      reject(null);
    } else {
      bcrypt.hash("ludosanu", 10, (error, hash) => error ? reject(error): resolve({ id: 1, password: hash }));
    }
  });
}

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use(morgan('dev'));

app.post('/signin', (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email(),
    password: Joi.string().min(8).max(20)
  });
  const { email, password } = req.body;
  
  const { error: schemaError, value: schemaValue } = schema.validate({ email, password });
  if (schemaError) {
    return res.status(401).send({ error: 'INVALID_EMAIL_OR_PASSWORD' });
  }

  const user = findUserByEmail(email);
  if (!user) {
    return res.status(401).send({ error: 'USER_NOT_FOUND' });
  }
  
  bcrypt.compare(password, user.password, (error) => {
    if (error) {
      return res.status(401).send({ error: 'INVALID_PASSWORD' });
    }
    const access_token = jwt.sign({ id: user.id }, JWT_SECRET);
    
    return res.status(200).send({ access_token });
  });
});

app.get('/protected', verifyBearerTokenMiddleware, (req, res, next) => {
  const decoded = jwt.decode(req.bearer_token);
  res.status(200).send({decoded});
});

// Error middleware
app.use((err, req, res, next) => {
  console.log('[ErrorMiddleware] Path: ', req.path);
  console.log('[ErrorMiddleware] Error: ', err);
  res.status(500).send(err.message);
});

// Run
app.listen(SERVER_PORT);
