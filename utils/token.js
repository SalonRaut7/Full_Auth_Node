const jwt = require('jsonwebtoken');

// Generate short-lived Access Token
function generateAccessToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
}

// Generate long-lived Refresh Token
function generateRefreshToken(user) {
  return jwt.sign(
    { id: user._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  );
}

module.exports = { generateAccessToken, generateRefreshToken };
