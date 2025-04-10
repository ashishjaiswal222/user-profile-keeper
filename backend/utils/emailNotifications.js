// utils/emailNotifications.js
const transporter = require('../config/mailer');
const { EMAIL_FROM } = process.env;

const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({ from: EMAIL_FROM, to, subject, html });
  } catch (error) {
    console.error(`Error sending email to ${to}:`, error);
  }
};

const notifyAllAdmins = async (subject, htmlContent, AdminModel) => {
  try {
    const admins = await AdminModel.findAll();
    const adminEmails = admins.map(a => a.email);
    if (adminEmails.length > 0) {
      await transporter.sendMail({
        from: EMAIL_FROM,
        to: adminEmails,
        subject,
        html: htmlContent
      });
    }
  } catch (err) {
    console.error('Error notifying admins:', err);
  }
};

module.exports = { sendEmail, notifyAllAdmins };
