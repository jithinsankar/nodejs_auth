const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require("dotenv").config();
const bcrypt = require('bcryptjs')

const app=express();
app.use(express.urlencoded({extended:true}));
const User= require("./user");



app.use(express.json());
mongoose.connect(`mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@cluster0.tzbyclt.mongodb.net/?retryWrites=true&w=majority`).then(()=>console.log("connected")).catch(err=>console.log(err));


let refreshTokens = []

app.post('/renewAccessToken',(req,res)=>{
    const refreshToken = req.body.token;

    if(!refreshToken || !refreshTokens.includes(refreshToken)){
        return res.status(403).json({message:"User not authenticated"});
    }

    jwt.verify(refreshToken,process.env.REFRESHTOKEN_SECRET,(err,user)=>{
        if(!err){
            const accessToken = jwt.sign({username:user.name},process.env.ACCESSTOKEN_SECRET,{expiresIn:'45s'})
            return res.status(201).json({accessToken});
        }
        else{
            return res.status(403).json({message:"User not authenticated"})
        }
    })
})

function auth(req,res,next){
    let token =req.headers['authorization'].split(' ')[1]
    jwt.verify(token,process.env.ACCESSTOKEN_SECRET,(err,user)=>{
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

app.post('/login',async(req,res)=>{

    const user = await User.findOne({username:req.body.username})

    if(!user){
        return res.status(404).json({message:'User not found'})
    }

    const isPasswordValid = await bcrypt.compare(req.body.password,user.password);

    if(isPasswordValid)
    {
        let accessToken = jwt.sign({'user':user.username},process.env.ACCESSTOKEN_SECRET,{expiresIn:'45s'});
        let refreshToken = jwt.sign({'user':user.username},process.env.REFRESHTOKEN_SECRET,{expiresIn:'1d'});
        refreshTokens.push(refreshToken)
        return res.status(201).json({
            accessToken,
            refreshToken
        });
    }
    else{
        return res.status(403).json({"message":"Wrong Password"})
    }

});

app.post('/register', async (req,res)=>{
    try{
        const { username, password, email } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            password:hashedPassword,
            email
        })
        console.log(newUser);
        const response = await newUser.save();
        res.send(`User ${username} created`)
        }
    catch(err){
        console.log(err);
        return res.status(403).json({"message":err.message})
    }
});

app.post('/forgotPassword',async (req,res)=>{
    const email = req.body.email;
    const user = await User.findOne({email})

    if(!user){
        return res.status(404).json({message:'User not found'})
    }

    const token = jwt.sign({email:user.email}, process.env.FORGOTPASSWORD_SECRET+user.password, {expiresIn:'10m' });
    const link = `http://localhost:3000/resetPassword/${token}`
    console.log(link);
    return res.status(201).json({"message":"Check your inbox"});
    
})


app.get('/resetPassword/:token',async (req,res)=>{

    const {token} = req.params;
    
    const email = await jwt.decode(token).email
    const user = await User.findOne({email})
    jwt.verify(token,process.env.FORGOTPASSWORD_SECRET+user.password,(err,email)=>{
        if(!err){
            res.send('<form action="/resetPassword" method="POST">' +
            '<input type="hidden" name="email" value="' + email.email + '" />' +
            '<input type="hidden" name="token" value="' + req.params.token + '" />' +
            '<input type="password" name="password" value="" placeholder="Enter your new password..." />' +
            '<input type="submit" value="Reset Password" />' +
        '</form>');
        }
        else{
            return res.status(403).json({"message":"Invalid token"})
        }
    })


})
app.post('/resetPassword',async (req,res)=>{

    const {email,token,password} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.findOne({email})
    jwt.verify(token,process.env.FORGOTPASSWORD_SECRET+user.password,(err,email)=>{
        if(!err){
            user.password = hashedPassword;
            user.save();
            res.send("Password reset successfull")
        }
        else{
            return res.status(403).json({"message":"Invalid token"})
        }
    })
});




app.listen(3000); 



