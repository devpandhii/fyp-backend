const mongoose=require('mongoose');
const resumeSchema=new mongoose.Schema({
    personalDetails: Object,
    educationDetails: Object,
    workExperience: Object,
    skillsDetails: Object,
    projectDetails: Object,
    certificationDetails: Object,
    publicationDetails: Object
})

const resumeModel=mongoose.model("resumeDetails",resumeSchema);
module.exports=resumeModel;
