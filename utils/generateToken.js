const jwt = require('jsonwebtoken');

/**
 * Generates a JSON Web Token for a given user ID.
 * @param {number} id The user's ID.
 * @returns {Promise<string>} A promise that resolves with the JWT.
 */
const generateToken = id => {
  return new Promise((resolve, reject) => {
    const payload = { user: { id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
};

module.exports = generateToken;