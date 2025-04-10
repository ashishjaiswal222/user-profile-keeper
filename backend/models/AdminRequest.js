// models/AdminRequest.js
const { sequelize } = require('../config/database');
const { DataTypes } = require('sequelize');

const AdminRequest = sequelize.define('AdminRequest', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  status: { type: DataTypes.ENUM('pending', 'approved', 'declined'), defaultValue: 'pending' }
});

module.exports = AdminRequest;
