// models/OTP.js
const { sequelize } = require('../config/database');
const { DataTypes } = require('sequelize');

const OTP = sequelize.define('OTP', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  email: { type: DataTypes.STRING, allowNull: false },
  otp: { type: DataTypes.STRING, allowNull: false }
});

module.exports = OTP;
