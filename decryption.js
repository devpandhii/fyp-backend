// decryption.js
const CryptoJS = require('crypto-js');

const SECRET_KEY = CryptoJS.enc.Hex.parse('a3bce21f8a2d9e1f4c3e5f6789abdef01234567890abcdef1234567890abcdef'); // Your generated key
const encryptedData = '3ZgBtlJxcS1YErUryx11kKiA/cnvkbxRjhEBHOQ981s+7XjFQn5mICyRn3ax789zXY73s6vbc2nK3Bx2MkziGA==';
const decryptData = (encryptedData) => {
  const data = CryptoJS.enc.Base64.parse(encryptedData);
  const iv = CryptoJS.lib.WordArray.create(data.words.slice(0, 4));
  const ciphertext = CryptoJS.lib.WordArray.create(data.words.slice(4));

  const decrypted = CryptoJS.AES.decrypt({ ciphertext: ciphertext }, SECRET_KEY, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
};

// module.exports = { decryptData };

// const decryptMiddleware = (req, res, next) => {
//   try {
//     const encryptedData = req.body.data;
//     console.log(encryptedData);
//     const decryptedData = decryptData(encryptedData);
//     req.body = decryptedData;
//     // logger.info(`Received request on /Login: ${JSON.stringify(req.body)}`);
//     console.log(decryptedData);
//     next();
//   } catch (error) {
//     logger.error(`Decryption error: ${error.message}`);
//     res.status(400).json({ message: 'Invalid data' });
//   }
// };

const decryptMiddleware = (req, res, next) => {
  if (req.body && req.body.data) {
    try {
      console.log(req.body.data);
      req.body = decryptData(req.body.data); 
      console.log("Decrypted data is: ",req.body);// Decrypt the data and replace the request body
    } catch (error) {
      return res.status(400).json({ error: 'Invalid encrypted data' });
    }
  }
  next(); // Proceed to the next middleware or route handler
};

module.exports = decryptMiddleware;