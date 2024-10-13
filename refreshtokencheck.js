const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;
require('dotenv').config();

const oauth2Client = new OAuth2({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: process.env.REDIRECT_URI,
});

const code = '4/0AcvDMrDdCo-v-C6Y8Yp8PozBzFQsQm14fmngdCaf_trbex8dOlUpZMFX-yuHWT4hIWcNWw'; // Replace with actual authorization code

oauth2Client.getToken(code, (err, tokens) => {
  if (err) {
    console.error('Error retrieving tokens:', err);
    return;
  }

  const { refresh_token, access_token, expiry_date } = tokens;

  // Store or use the refresh_token for future token refreshes
  console.log('New refresh token:', refresh_token);
  console.log('Access token:', access_token);
  console.log('Token expiry date:', expiry_date);
});
