const { google } = require('googleapis');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const oauth2Client = new OAuth2Client({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: process.env.REDIRECT_URI,
});

oauth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN,
});


async function sendEmail(email, token) {
  try {
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const resetLink = `http://localhost:3000/reset-password?token=${token}&reset=true`;

    const emailContent = `From: hrsshah04022004@gmail.com\r\n` +
      `To: ${email}\r\n` +
      `Subject: Test Email using OAuth2\r\n\r\n` +
      `Please click the following link to reset your password:\r\n\r\n${resetLink}`;
    const raw = Buffer.from(emailContent).toString('base64');

    const result = await gmail.users.messages.send({
      userId: 'me',
      requestBody: {
        raw: raw,
      },
    });

    console.log('Email sent successfully:', result.data);
    return result.data;
  } catch (error) {
    console.error('Error sending email:', error.message);
    throw error;
  }
}

module.exports = sendEmail;
