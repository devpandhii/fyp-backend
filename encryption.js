const CryptoJS = require('crypto-js');

const SECRET_KEY = CryptoJS.enc.Hex.parse('a3bce21f8a2d9e1f4c3e5f6789abdef01234567890abcdef1234567890abcdef'); // Your generated key

// const encryptData = (data) => {
//   try {
//     console.log("Data before encryption:", data);

//     const iv = CryptoJS.lib.WordArray.random(16);
//     console.log("Generated IV:", iv.toString(CryptoJS.enc.Hex));

//     const jsonString = JSON.stringify(data);
//     console.log("Stringified data:", jsonString);

//     const encrypted = CryptoJS.AES.encrypt(jsonString, SECRET_KEY, {
//       iv,
//       mode: CryptoJS.mode.CBC,
//       padding: CryptoJS.pad.Pkcs7,
//     });

//     console.log("Encrypted ciphertext:", encrypted.ciphertext.toString(CryptoJS.enc.Base64));

//     const encryptedData = iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Base64);
//     console.log("Final encrypted data (Base64):", encryptedData);

//     return encryptedData;
//   } catch (error) {
//     console.error("Encryption error:", error);
//     throw error;
//   }
// };



// const apiClient = axios.create({
//   baseURL: 'http://localhost:5000',
//   // withCredentials: true,
// });

// apiClient.interceptors.request.use((config) => {
//   if (config.data) {
//     console.log("Original config data: ", config.data);
//     try {
//       // Encrypt the data
//       const encrypted = encryptData(config.data);
//       console.log("Encrypted data: ", encrypted);

//       // Set the encrypted data in the request payload
//       config.data = { data: encrypted };
//       console.log('Final request data after encryption: ', config.data);
//     } catch (error) {
//       console.error("Failed to encrypt data:", error);
//     }
//   } else {
//     console.log("No data found in config to encrypt.");
//   }
//   return config;
// }, (error) => {
//   console.error("Error in request interceptor: ", error);
//   return Promise.reject(error);
// });

// export { encryptData, apiClient };


// apiClient.interceptors.response.use(
//     (response) => {
//       if (response.data) {
//         try {
//           // Decrypt the response data
//           const encryptedData = encryptData(response.data);
//           console.log("Encrypted Apiclient data: ", encryptedData);
  
//           // Replace the encrypted data with the decrypted data
//           response.data = encryptedData;
//         } catch (error) {
//           console.error("Failed to encrypt response data:", error);
//         }
//       } else {
//         console.log("No encrypted data found in response.");
//       }
//       return response;
//     },
//     (error) => {
//       console.error("Error in response interceptor: ", error);
//       return Promise.reject(error);
//     }
//   );
  
//   export { encryptData, apiClient };

const encryptData = (data) => {
    try {
      console.log("Data before encryption:", data);
  
      // Generate a random Initialization Vector (IV)
      const iv = CryptoJS.lib.WordArray.random(16);
      console.log("Generated IV:", iv.toString(CryptoJS.enc.Hex));
  
      // Convert the JSON object to a string
      const jsonString = JSON.stringify(data);
      console.log("Stringified data:", jsonString);
  
      // Encrypt the JSON string
      const encrypted = CryptoJS.AES.encrypt(jsonString, SECRET_KEY, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
  
      console.log("Encrypted ciphertext:", encrypted.ciphertext.toString(CryptoJS.enc.Base64));
  
      // Concatenate IV and ciphertext, then convert to Base64 for transmission
      const encryptedData = iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Base64);
      console.log("Final encrypted data (Base64):", encryptedData);
  
      return encryptedData;
    } catch (error) {
      console.error("Encryption error:", error);
      throw error;
    }
  };

module.exports = encryptData;
  