const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require("dotenv").config();
const app=express();
const User= require("./user");



app.use(express.json());
mongoose.connect(`mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@cluster0.tzbyclt.mongodb.net/?retryWrites=true&w=majority`).then(()=>console.log("connected")).catch(err=>console.log(err));


let refreshTokens = []

app.post('/renewAccessToken',(req,res)=>{
    const refreshToken = req.body.token;

    if(!refreshToken || !refreshTokens.includes(refreshToken)){
        return res.status(403).json({message:"User not authenticated"});
    }

    jwt.verify(refreshToken,'refresh',(err,user)=>{
        if(!err){
            const accessToken = jwt.sign({username:user.name},'access',{expiresIn:'45s'})
            return res.status(201).json({accessToken});
        }
        else{
            return res.status(403).json({message:"User not authenticated"})
        }
    })
})

function auth(req,res,next){
    let token =req.headers['authorization'].split(' ')[1]
    jwt.verify(token,'access',(err,user)=>{
        if(!err){
            req.user = user;
            next();
        }
        else{
            return res.status(403).json({"message":"User not authenticated"})
        }
    })
}

app.post('/protected',auth,(req,res)=>{
    res.json(req.user)
})

app.post('/login',(req,res)=>{
    const user = req.body.user;
    const password = req.body.password;
    if(!user){
        return res.status(404).json({message:'Body Empty'})
    }

        let accessToken = jwt.sign({user:user.username},'access',{expiresIn:'45s'});
        let refreshToken = jwt.sign({user:user.username},'refresh',{expiresIn:'1d'});
        refreshTokens.push(refreshToken)
        return res.status(201).json({
            accessToken,
            refreshToken
        });

});

app.post('/register',(req,res)=>{
    try{
        const { username, password } = req.body;
        const newUser = new User({
            username,
            password
    })
    console.log(newUser);
    newUser.save();
}
catch(err){
    console.log(err);
}
});



app.listen(3000); 



