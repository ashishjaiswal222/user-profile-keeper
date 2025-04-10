// config/mailer.js
const nodemailer = require('nodemailer');
require('dotenv').config();

let transporterConfig = {};
if (process.env.EMAIL_SERVICE) {
  transporterConfig = {
    service: process.env.EMAIL_SERVICE,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  };
} else {
  transporterConfig = {
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  };
}

const transporter = nodemailer.createTransport(transporterConfig);

module.exports = transporter;
