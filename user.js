const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const User= new Schema({
    username:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true,
        unique:true
    }
})
const model = mongoose.model("userModel",User);
module.exports = model;