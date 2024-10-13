// require('dotenv').config();
// const mongoose=require('mongoose');
// const connectionParams={
//     useNewUrlParser: true,
//     useCreateIndex: true,
//     useUnifiedTopology: true
// }
// const db = process.env.DATABASE_URL;
// const url=`mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0.fr3nmca.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0` 
// const connection=mongoose.connect(url).then(()=>{console.log("Connected to cloud atlas")}).catch((err)=>{console.log(err)});
// connection.js
require('dotenv').config();

const mongoose = require('mongoose');
const db = process.env.DATABASE_URL;

const connection=mongoose.connect(db)
.then(() => console.log('Database connected successfully'))
.catch(err => console.error('Database connection error:', err));

module.exports=connection;