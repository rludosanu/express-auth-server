/*
 * Load environment
 */
require('dotenv').config({
  path: `./src/config/.env.${process.env.NODE_ENV || 'development'}`
});

/*
 * Load dependencies
 */
const express = require('express');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Sequelize } = require('sequelize');
// const nodemailer = require("nodemailer");
// const mailer = nodemailer.createTransport({
  
// });

class ValidationError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = statusCode || 500;
  }
}

/*
 * Start application
 */
(async () => {
  try {
    /* Extract environment variables */
    const {
      DATABASE_NAME,
      DATABASE_USER,
      DATABASE_PASSWORD,
      DATABASE_HOST,
      DATABASE_PORT,
      DATABASE_DIALECT,
      DATABASE_SYNC,
      DATABASE_LOGGING,
      SERVER_PORT,
      NODE_ENV,
      JWT_SECRET
    } = process.env;

    /* Connect to the database */
    const db = new Sequelize(DATABASE_NAME, DATABASE_USER, DATABASE_PASSWORD, {
      host: DATABASE_HOST,
      port: DATABASE_PORT,
      dialect: DATABASE_DIALECT,
      logging: DATABASE_LOGGING && true || false
    });

    await db.authenticate();

    /* Create and sync models (tables) */
    const models = {
      user: db.define('user', {
        id: {
          type: Sequelize.INTEGER,
          primaryKey: true,
          allowNull: false,
          autoIncrement: true
        },
        email: {
          type: Sequelize.STRING,
          allowNull: false,
          required: true,
          unique: true
        },
        password: {
          type: Sequelize.STRING,
          allowNull: false,
          required: true
        }
      })
    };

    await db.sync({ force: DATABASE_SYNC && true || false });

    /* Populate database (in dev mode only) */
    if (NODE_ENV === 'development') {
      await models.user.create({
        email: 'razvan@gmail.com',
        password: '$2b$10$MBNE7uqC3Gq3ieF6K..3fe8YCsegseainMNCPCTAhL8Lkz82.ksOO' // Hash value of "password"
      });
    }

    /* Create a new Express application */
    const server = express();

    /* Create a new router for authentication */
    const routes = {
      auth: express.Router()
    };

    /* Use body parsing middlewares */
    server.use(bodyParser.urlencoded({ extended: true }));
    server.use(bodyParser.json());

    /* Use logging middleware */
    server.use(morgan('dev'));

    /* Define user sign in route */
    routes.auth.post('/signin', async (req, res) => {
      // Define the data schema
      const schema = Joi.object({
        email: Joi.string().email(),
        password: Joi.string().min(6).max(20)
      });
      
      // Extract the email and password fields
      const { email, password } = req.body;
  
      try {
        // Verify that the fields match the expected format
        let { error } = schema.validate({ email, password });
        if (error) {
          throw new ValidationError('INVALID_EMAIL_OR_PASSWORD', 400);
        }
  
        // Find matching user in database from email
        const user = await models.user.findOne({
          where: {
            email
          }
        });
        if (!user) {
          throw new ValidationError('USER_NOT_FOUND', 401);
        }
    
        // Check if the request password and the database hash are matching
        const isPasswordIdentical = await bcrypt.compare(password, user.password);
        if (!isPasswordIdentical) {
          throw new ValidationError('INCORRECT_PASSWORD', 401);
        }
    
        // Generate and send an access token containing the user's ID
        const access_token = jwt.sign({ id: user.id }, JWT_SECRET);

        return res.status(200).send({ access_token });
      } catch(error) {
        // Display the error and return
        console.error(error.message, error.statusCode);
        return res.sendStatus(error.statusCode || 401);
      }
    });

    routes.auth.post('/signup', async (req, res) => {
      const schema = Joi.object({
        email: Joi.string().email(),
        password: Joi.string().min(6).max(20)
      });
      
      const { email, password } = req.body;
  
      try {
        let { error } = schema.validate({ email, password });
        if (error) {
          throw new ValidationError('INVALID_EMAIL_OR_PASSWORD', 400);
        }

        const hash = await bcrypt.hash(password, 10);
        const newUser = await models.user.create({ email, password: hash });
    
        res.sendStatus(200);
      } catch(error) {
        console.error(error.message, error.statusCode);
        return res.sendStatus(error.statusCode || 500);
      }
    });

    routes.auth.post('/lost-password', async (req, res) => {
      const schema = Joi.object({
        email: Joi.string().email(),
      });

      const generateRandomPassword = () => {
        const base = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let password = '';
      
        for (let i = 0; i < 8; i++) {
          password += base.charAt(Math.floor(Math.random() * base.length));
        }
        return password;
      };
      
      const { email } = req.body;
  
      try {
        let { error } = schema.validate({ email });
        if (error) {
          throw new ValidationError('INVALID_EMAIL', 400);
        }

        const password = generateRandomPassword();
        const hash = await bcrypt.hash(password, 10);

        const [updateCount] = await models.user.update({ password: hash }, { where: { email }});
        if (!updateCount) {
          let e = new Error('USER_NOT_FOUND');
          e.statusCode = 401;
          throw e;
        }

        // Send new password with email...

        res.sendStatus(200);
      } catch(error) {
        console.error(error.message, error.statusCode);
        return res.sendStatus(error.statusCode || 500);
      }
    });

    /* Use the authentication router */
    server.use('/api/auth', routes.auth);
    
    /* Send a "404 Not found" to all unmatched requests */
    server.all('*', (req, res) => res.sendStatus(404));
    
    /* Start server */
    server.listen(SERVER_PORT, () => {
      console.log(`Express server up and running on port ${SERVER_PORT} in ${NODE_ENV} mode.`);
    });
  } catch(error) {
    /* Display error and exit */
    console.error(error);
    process.exit(1);
  }
})();
