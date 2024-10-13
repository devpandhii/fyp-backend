// const express=require('express')
//const mongoose=require('mongoose');
// const userModel=require('./models/userModels');
// const app=express();
// const db=require('./connection');
// app.use(express.urlencoded({extended: true}))

// app.post('/Register',async(req,res)=>{
//     const {name,email,password}=req.body;
//     try {
//         const newUser = new Post({name,email,password});
//         await newUser.save();
//         res.status(201).send('User registered successfully');
//       } catch (error) {
//         res.status(500).send('Error registering user');
//       }
// })

// app.listen(3000,()=>{
//     console.log("Listen to 3000");
// })
// mongoose.connect("mongodb+srv://manavrathod115:SN0o51NJXhOL3xRG@cluster0.fr3nmca.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

// const User=require('./models/userModels')
// app.listen(3000,()=>{
//     console.log("Server is running on port 3000")
// })