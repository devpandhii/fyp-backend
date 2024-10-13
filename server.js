const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();
const sendEmail = require('./email');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const logger = require('./logger');
const cookieParser = require('cookie-parser');
const Cookies = require('universal-cookie'); 
const session = require('express-session');
const MongoStore = require('connect-mongo');
// const verifyToken=require('./verfiytoken')
let tokenavail;
// const cookies=new Cookies();
const crypto = require('crypto');
const decryptMiddleware = require('./decryption');
const { strict } = require('assert');
const { error } = require('console');
const passport = require('passport');
const multer=require('multer');
const path=require('path');
const ImgModel=require('./Models/imageModel');
const OpenAI = require("openai");
const encryptData  = require('./encryption');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const resumeModel=require('./Models/ResumeModel')

// const configuration = new Configuration({
//     apiKey: process.env.OPENAI_API_KEY
// });


const app = express();
const port = process.env.PORT;
app.use(express.static('public'));
// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(cookieParser());
app.use(decryptMiddleware);

mongoose.connect("mongodb+srv://user2000:test369@cluster0.fr3nmca.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0");
const db = mongoose.connection;

// Define a schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    // required: true,
    unique: true
  },
  email: {
    type: String,
    // required: true,
  },
  password: {
    type: String,
    // required: true
  }
});

const User = mongoose.model('Registration', userSchema);

const profileSchema=new mongoose.Schema({
  username: {
    type: String,
    required: true,
    // unique: true
  },
  email:{
    type:String,
  },
  password: {
    type: String,
    },
  age:{
    type: Number,
  },
  mobile:{
    type: Number,
  },
  city:{
    type: String,
    },
  image:{
    type: String,
  }
});
const Profile = mongoose.model('Profile', profileSchema);

//image---------------------------------------------------------------------------------------------------------------------
const storage=multer.diskStorage({
  destination: (req,file,cb)=>{
    cb(null,'public/images')
  },
  filename: (req,file,cb)=>{
    cb(null,file.fieldname+"_"+Date.now()+path.extname(file.originalname))
  }
});

const upload=multer({
  storage: storage,
});
//for upload for image in image collection ---(POC)
// app.post('/upload',upload.single('selectedFile'),(req,res)=>{
//   console.log(req.file);
//   // res.send("File Recieved");
//   ImgModel.create({image: req.file.filename})
//   .then(result=>res.send(result))
//   .catch(err=>console.log(err));
// })

// app.get('/getImage',(req,res)=>{
//   ImgModel.find()
//   .then(user=>res.json(user))
//   .catch(err=>res.json('Error: '+err));
// })
//--------------------------------------------------------------------------------------------------------------------------

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
// app.post('/Profile',(req,res)=>{
//   const {username,age,mobile,city}=req.body;
//   console.log(req.body);
//   User.find({username})
//   .then((user)=>{
//     try
//     {
//     const newProfile=new Profile({username,age,mobile,city})
//     newProfile.save();
//     // res.json(newProfile,{message: "Profile Created"});
//     console.log(newProfile);
//     }
//     catch(error)
//     { 
//       res.json(error);
//     }
//   })
//   .catch(error=>{
//     res.json(error);
//   })
// })
app.put('/profile',upload.single('File'),(req,res)=>{
  logger.info(`Received request on /profile: ${JSON.stringify(req.body)}`);
  const {age,mobile,city}=req.body;
  const image=req.file.filename;
  console.log(req.file);
  const {identifier}=req.query;
  Profile.updateOne({username: identifier},{$set: {age:age,mobile:mobile,city:city,image: image}})
  // ImgModel.create({image: req.file.filename})
  .then(user=>res.status(200).json({message: "Profile Data Updated"}))
  .catch(error=>res.json(error))
})

// const SECRET_KEY = 'a3bce21f8a2d9e1f4c3e5f6789abdef01234567890abcdef1234567890abcdef';
// const decryptData = (encryptedData) => {
//   const decipher = crypto.createDecipheriv('aes-256-cbc', SECRET_KEY, Buffer.alloc(16, 0));
//   let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
//   decrypted += decipher.final('utf8');
//   return JSON.parse(decrypted);
// };

// Define a POST route to handle data submission
app.post('/Registration', async (req, res) => {
  logger.info(`Received request on /Registration: ${JSON.stringify(req.body)}`);
  const { username, email, password } = req.body;
  console.log("This is req.body :",req.body);
  try {
    const user = await User.findOne({ username });

    if (user) {
      res.status(200).json({ message: "Username already exists" });
    } else {
      const newUser = new User({ username, email, password });
      await newUser.save();
      const newProfile=new Profile({username,email,password});
      await newProfile.save();
      res.status(200).json({ message: "Form submitted", newUser,newProfile });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});



//Login part
app.post('/login', (req, res) => {
  // let req={"username":"anshumandas123","password":"anshumandas@123"};
  logger.info(`Received request on /Login: ${JSON.stringify(req.body)}`);
  // const {username,password}=req.body;
  // const encryptedData = req.body.data;
  // const {username,password} = decryptData(encryptedData);
  const { username, password } = req.body;
  console.log("this is jingalala:",req.body);
  User.findOne({ username: username })
    .then(user => {
      console.log("chenka: " ,user);
      console.log("chenka jhenu: " ,user.password);
      if (user) {
      console.log("chenka jhenu: " ,user);

        if (user.password === password) {
      console.log("chenka jhenu: " ,user.password, user.username);
          console.log("This is the topa: ",username,password);
          const token = jwt.sign({ username: username, password: password }, process.env.JWT_SECRET, { expiresIn: '40m' });
          console.log("Login Cookie", token);
          res.cookie('token', token, { httpOnly: false, secure: true, sameSite: 'Strict' });
          // console.log(token);
          // cookies.set("authCookies",token);
          tokenavail = token;
          // console.log(tokenavail)
          // res.cookie('authtoken',token,{httpOnly: true, secure: true});
          // res.setHeader('set-Cookie',`authorizationCookie=${token};`);
          // console.log(req.cookies.token);
          // const token=jwt.sign({username:uname,password:upass},process.env.JWT_SECRET,{expiresIn: '1h'});
          res.status(200).json({ status: "success", user, token });
          // console.log(user);
        }
        else {
          res.json("Incorrect password");
        }
      }
      else {
        res.json("Invalid Credentials");
      }
    }).catch((error) => {
      logger.error(`Database error: ${error.message}`);
      res.status(500).json({ message: 'Internal Server Error' });
    });
});

app.post('/verify-token', (req, res) => {
  const token = req.cookies.token;
  // const {bt,maintoken}=req.body;
  console.log(req.body);
  // const {username}=req.body;
  // console.log(req)
  // console.log(token);
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token.toString(), process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(403).json({ message: 'Token verification failed' });
    }

    console.log("Verification Done");

    // Assuming decryptedData contains the decrypted username and password from middleware
    console.log("before jwt decode: ",token);
    const decodetoken = jwt.decode(token);
    console.log(decodetoken);
    const { username , password }=decodetoken;
    console.log(username,password);
    Profile.findOne({ username: username }).then(user => {
      if (!user) {
        return res.status(404).json({ message: 'User Not found' });
      }
      const userName=user.username;
      const userPassword=user.password;
      const userEmail = user.email;
      const userAge=user.age;
      const userMobile=user.mobile;
      const userCity=user.city;
      const profileImage=user.image;
      // const id=user._id;

      const response = {
        decodetoken: {
          username: userName,
          password: userPassword,
          email: userEmail,
          age:userAge,
          mobile:userMobile,
          city:userCity,
          profileImage:profileImage,
        }
      };
      const encryptedResponse = encryptData(response);
      console.log(encryptedResponse);
      res.json(encryptedResponse);
      console.log(encryptedResponse);
    }).catch(error => {
      console.log('Error Fetching User: ', error.message);
      res.status(500).json({ message: 'Internal Server Error' });
    });
  });



  // You can further process username and password here
  // Example: Query user data from database based on username

  // res.json({decodetoken}); // Sending decrypted username and password back to client
});

//This code checks the user and authenticates the user
app.get('/checkAuth', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ isAuthenticated: false });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.json({ isAuthenticated: false });
    }
    return res.json({ isAuthenticated: true });
  });
});


const verifyToken = (req, res, next) => {
  const token = tokenavail;
  console.log(token);

  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Failed to authenticate token' });
    }
    req.user = decoded; // Store the decoded token in the request object
    // req.username = decoded.username;
    req.user = decoded;
    // req.userId=decoded.id;
    next();
  });
};



// app.get('/home',verifyToken,(req,res)=>{
//   res.json({message: 'Welcome to homePage'});
// });

let usedTokens = {};

app.post('/forget-pass',decryptMiddleware, async (req, res) => {
  const email = req.body.email;
  console.log("this is email",req.body.email);
  console.log("Email Variable: ", email );
  try {
    const user = await User.findOne({ email });
    console.log(email);
    if (!user) {
      return res.json("Invalid Email");
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '20m' });
    // console.log(token)
    usedTokens[token] = false;
    user.resetPasswordToken = token;
    await user.save();

    // Call sendEmail function with email parameter
    const result = await sendEmail(email, token);
    res.status(200).json({ message: 'Email sent successfully', data: result });

  } catch (error) {
    console.error('Error sending email:', error.message);
    res.status(500).json({ message: 'Failed to send email', error: error.message });
  }
});

app.get('/verify-reset-token', (req, res) => {
  const { token } = req.query;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (usedTokens[token]) {
      return res.status(400).json({ valid: false, message: 'Token has already been used' });
    }
    res.status(200).json({ valid: true, email: decoded.email });
  } catch (error) {
    res.status(400).json({ valid: false, message: 'Session Expired' });
  }
});

// const router = express.Router();

app.put('/reset-password',async (req,res)=>{
  logger.info(`Received request on /reset-password: ${JSON.stringify(req.body)}`);
  const {password}=req.body;
  const {identifier}=req.query;
  const {token}=req.query;
  console.log(password);
  console.log(identifier);
  console.log("The token is: ",token);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    if (usedTokens[token]) {
      return res.status(400).json({ message: 'Token has already been used.' });
    }

    const result = await User.updateOne({ email }, { $set: { password } });
    usedTokens[token] = true;
    res.json({ message: 'Password updated successfully', result });
  } catch (error) {
    console.error('Error verifying token or updating password:', error.message);
    res.status(400).json({ message: 'Session expired or invalid token', error: error.message });
  }
  // User.updateOne({email: identifier},{$set: {password: password}})
  // .then(result=>res.json(result))
  // .catch(error=>res.json(error))
})


app.post('/refreshtoken',(req,res)=>{
  const refreshToken = req.cookies.token;
  // const refreshToken=req.body;
  console.log(refreshToken);
  const decodeToken=jwt.decode(refreshToken);
  console.log(decodeToken);
  const username=decodeToken.username;
  const password=decodeToken.password;
  res.clearCookie('token',{httpOnly: false, secure:true,sameSite:'Strict'});

  console.log("Username: ",username," &  password: ",password);
  const newToken=jwt.sign({username,password},process.env.JWT_SECRET,{expiresIn: '40m'});
  // res.cookie('refresh',newToken,{httpOnly: false,secure: true});
  res.cookie('token',newToken,{httpOnly: false,secure: true});
  res.status(200).json({status: "Success", message: "Refresh token set successfully",newToken});
})

//All user data
app.get('/getUsers',(req,res)=>{
  Profile.find({})
  .then(result=>res.json(result))
  .catch(error=>res.json(error))
})

// app.get('/Registration', async (req, res) => {
//   const {identifier}=req.query;
//   try {
//     const items = await User.findOne({username:identifier});
//     res.json(items);
//   } catch (err) {
//     res.status(500).send(err);
//   }
// });


// const verifyToken = (req, res, next) => {
//   // const token = tokenavail;
//   const token=req.cookies.token;
//   console.log(token);

//   if (!token) {
//     return res.status(403).json({ message: 'No token provided' });
//   }

//   jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
//     if (err) {
//       return res.status(401).json({ message: 'Failed to authenticate token' });
//     }
//     req.user = decoded; // Store the decoded token in the request object
//     // req.username = decoded.username;
//     req.user = decoded;
//     // req.userId=decoded.id;
//     next();
//   });
// };
// update
app.put('/update', (req, res) => {
  logger.info(`Received request on /update: ${JSON.stringify(req.body)}`);
  const { username, email, password, age, mobile, city } = req.body;
  console.log(req.body);
  const { identifier } = req.query;
  const token = req.cookies.token;
  console.log(token);

  if (username || email || password) {
    User.findOneAndUpdate({ username: identifier }, { $set: { username, email, password } }, { new: true })
      .then(user => {
        return Profile.findOneAndUpdate({ username: identifier }, { $set: { username, email, password, age, mobile, city } }, { new: true });
      })
      .then(profile => {
        res.clearCookie('token', { httpOnly: false, secure: true, sameSite: 'Strict' });
        const updatedUsername = profile.username;
        const updatedPassword = profile.password;
        console.log("baigan lelo", updatedUsername, updatedPassword);

        // Generate new token
        const newToken = jwt.sign({ username: updatedUsername, password: updatedPassword }, process.env.JWT_SECRET, { expiresIn: "40m" });
        res.cookie('token', newToken, { httpOnly: false, secure: true, sameSite: 'Strict' });
        res.status(200).json({ status: "Success", profile, token: newToken,message: "Profile updated Successfully" });
      })
      .catch(err => res.status(500).send(err));
  } else {
    Profile.findOneAndUpdate({ username: identifier }, { $set: { email, password, age, mobile, city } }, { new: true })
      .then(profile => {
        console.log(profile);
        const latestToken = jwt.sign({ username: profile.username, password: profile.password }, process.env.JWT_SECRET, { expiresIn: "40m" });
        res.cookie('token', latestToken, { httpOnly: false, secure: true, sameSite: 'Strict' });
        res.status(200).json({ status: "Success", message: "Profile updated Successfully", profile, latestToken });
      })
      .catch(err => res.status(500).send(err));
  }
});

//Delete user
app.delete('/deleteUser/:id', async (req, res) => {
  const userId = req.params.id;
  console.log(`Received request to delete user with ID: ${userId}`);
  
  try {
    const deletedProfile = await Profile.findByIdAndDelete(userId);
    if (deletedProfile) {
      console.log('Profile deleted successfully:', deletedProfile);
      const deletedUser = await User.deleteOne({ username: deletedProfile.username });
      console.log('User deleted successfully:', deletedUser);

      res.status(200).send({ message: 'User deleted successfully from both collections', deletedProfile, deletedUser });
    } else {
      console.log('Profile not found with ID:', userId);
      res.status(404).send({ message: 'Profile not found' });
    }
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).send(err);
  }
});

//newUser
app.post('/newUser', async (req, res) => {
  const { username, email, password, age, mobile, city } = req.body;
  try {
    const user = new User({ username, email, password });
    await user.save();
    
    const newProfile = new Profile({ username, email, password, age, mobile, city });
    await newProfile.save();
    
    res.status(200).json({ message: 'User created successfully', user, newProfile });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


//update user
app.put('/updateUser/:id', async (req, res) => {
  const userId = req.params.id;
  const { username, email, password, age, mobile, city } = req.body;
  try {
    // Update Profile
    const profile = await Profile.findByIdAndUpdate(userId, req.body, { new: true });
    
    if (profile) {
      // Update User
      await User.updateOne(
        { username: profile.username },
        { $set: { username, email, password } }
      );
      
      res.status(200).json({ message: 'User updated successfully', profile });
    } else {
      res.status(404).json({ message: 'Profile not found' });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});



//Password generator according to our defined Password Regex
function generatePassword() {
  const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const specialChars = "@$!%*?&#";
  const allChars = letters + digits + specialChars;

  let password = '';
  password += letters.charAt(Math.floor(Math.random() * letters.length));
  password += digits.charAt(Math.floor(Math.random() * digits.length));
  password += specialChars.charAt(Math.floor(Math.random() * specialChars.length));
  
  for (let i = password.length; i < 8; i++) {
    password += allChars.charAt(Math.floor(Math.random() * allChars.length));
  }
  password = password.split('').sort(() => Math.random() - 0.5).join('');
  return password;
}


passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:5000/auth/google/callback",
  scope: ['profile', 'email'] // Add 'email' scope to retrieve email address
},
async (accessToken, refreshToken, profile, done) => {
  try {
    // Profile should now include email if granted by the user
    console.log('Google Profile:', profile);
    console.log('Google Email: ', profile._json.email);
    console.log('Google username: ', profile.displayName);

    // Check if displayName is available
    if (!profile.displayName) {
      return done(new Error('Google profile displayName not provided'), false);
    }

    // Handle user creation or authentication based on email
    const existingUser = await User.findOne({ username: profile.displayName });
    const existingProfile = await Profile.findOne({ username: profile.displayName });

    if (!existingUser || !existingProfile) {
      const newProfile = await Profile.create({
        username: profile.displayName,
        email: profile._json.email || 'google-email', 
        password: generatePassword()
        // Additional fields based on your schema
      });
      done(null,newProfile);
      const newUser = await User.create({
        username: profile.displayName,
        email: profile._json.email || 'google-email', 
        password: generatePassword()
        // Additional fields based on your schema
      });
      done(null, newUser);
    } else {
      done(null, existingUser);
    }
  } catch (err) {
    done(err, false, err.message);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, false, err.message);
  }
});

app.use(session({
  secret: 'f4ba248522394655cdbc54ec47e4387a3a1cfeb356df32ad348fed0b76a09918',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: 'mongodb+srv://user2000:test369@cluster0.fr3nmca.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'})
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: 'http://localhost:3000' }),
  (req, res) => {

    res.cookie('username', req.profile.username,{httpOnly:true});
    res.cookie('email', req.profile.email,{httpOnly:true});

    // Successful authentication, redirect to the profile completion page
    res.redirect('http://localhost:3000/home'); // Redirect to the profile completion page
  }
);

app.get('/auth/google/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ message: 'Successful Google login' });
  } else {
    res.json({ message: 'Not authenticated' });
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('http://localhost:3000');
  });
});

app.post('/complete-profile', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Find the authenticated user (assumes user is authenticated)
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Update user profile with additional information
    user.username = username;
    user.email = email;
    user.password = password; // Make sure to hash the password before saving

    await user.save();

    res.json({ success: true, message: 'Profile completed successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/checkUserName', async (req, res) => {
  const { username } = req.body;
  try {
    const user = await Profile.findOne({ username }); 
    if (user) {
      res.status(200).json({ message: "Username already exists" });
    } else {
      res.status(200).json({ message: "Username available" });
    }
  } catch (error) {
    res.status(500).json({ error: "An error occurred" });
  }
});

//Resume Details in Our MongoDB
app.post('/resumeDetails',(req,res)=>{

  console.log(req.body);
  const {personalDetails,educationDetails,workExperience,skillsDetails,projectDetails,certificationDetails,publicationDetails}=req.body;
  console.log("Data from req.body: ",{personalDetails,educationDetails,workExperience,skillsDetails,projectDetails,certificationDetails,publicationDetails});
  try{
    const resume=new resumeModel(req.body);
    resume.save();
    res.status(200).json("Data entered successfully")
  }
  catch(error)
  {
    res.status(200).json("Error occurred: ",error);
  }
})


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// module.exports = User;