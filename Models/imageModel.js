const mongoose=require('mongoose');
const imgSchema=new mongoose.Schema({
    image: String,
})
const ImgModel=mongoose.model("images",imgSchema);
module.exports=ImgModel;