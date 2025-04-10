// app.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const { sequelize } = require('./config/database');

// Import routes
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Mount routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);

// Serve static frontend files (assumes frontend is in ../frontend)
// Serve static files from the project root (where index.html is located)
app.use(express.static(path.join(__dirname, '..')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../index.html'));
});


// Root route
app.get('/', (req, res) => res.send('User Profile Keeper API is running.'));

// Connect to the database and start the server
sequelize.authenticate()
  .then(() => {
    console.log('PostgreSQL connection established.');

    // Sync your models to the database
    return sequelize.sync(); // ✅ add this
  })
  .then(() => {
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  })
  .catch(err => {
    console.error('Unable to connect to the database:', err);
    process.exit(1);
  });

