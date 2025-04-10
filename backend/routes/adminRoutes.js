// routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const { User, Admin } = require('../models');
const { sendEmail, notifyAllAdmins } = require('../utils/emailNotifications');
const authMiddleware = require('../middleware/authMiddleware');

// 1. Get Admin Profile
router.get('/profile', authMiddleware('admin'), async (req, res) => {
  try {
    const admin = await Admin.findOne({ where: { id: req.user.id } });
    if (!admin) return res.status(404).json({ error: 'Admin not found.' });
    res.status(200).json({ admin });
  } catch (error) {
    console.error('Admin profile error:', error);
    res.status(500).json({ error: 'Server error fetching admin profile.' });
  }
});

// 2. Get All Users (Admin)
router.get('/users', authMiddleware('admin'), async (req, res) => {
  try {
    const users = await User.findAll();
    res.status(200).json({ users });
  } catch (error) {
    console.error('Admin get users error:', error);
    res.status(500).json({ error: 'Server error fetching users.' });
  }
});

// 3. Delete User (Admin)
router.post('/delete-user', authMiddleware('admin'), async (req, res) => {
  try {
    const { userId, userEmail, message } = req.body;
    const deletion = await User.destroy({ where: { id: userId } });
    if (!deletion) return res.status(400).json({ error: 'User deletion failed.' });
    await sendEmail(userEmail, 'Account Deletion Notification', `<p>Your account has been deleted.</p><p>Message: ${message}</p>`);
    await notifyAllAdmins('User Deleted', `<p>User with email ${userEmail} has been deleted. Message: ${message}</p>`, Admin);
    res.status(200).json({ message: 'User deleted successfully.' });
  } catch (error) {
    console.error('Admin delete user error:', error);
    res.status(500).json({ error: 'Server error during user deletion.' });
  }
});

// 4. Block User (Admin)
router.post('/block-user', authMiddleware('admin'), async (req, res) => {
  try {
    const { userId, userEmail, message } = req.body;
    const user = await User.findOne({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: 'User not found.' });
    await user.update({ isBlocked: true });
    await sendEmail(userEmail, 'Account Block Notification', `<p>Your account has been blocked.</p><p>Message: ${message}</p>`);
    await notifyAllAdmins('User Blocked', `<p>User with email ${userEmail} has been blocked. Message: ${message}</p>`, Admin);
    res.status(200).json({ message: 'User blocked successfully.' });
  } catch (error) {
    console.error('Admin block user error:', error);
    res.status(500).json({ error: 'Server error during user blocking.' });
  }
});

module.exports = router;
