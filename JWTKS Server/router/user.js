const express = require('express')
const router = express.Router()
const knex =require('../config/Database');
const bcrypt=require('bcrypt');
const jwt = require('jsonwebtoken');
const authorization = require("../middleware/authorization");



router.post('/register', async (req, res) => {
    let {email} =req.body;
    let {password} =req.body; 
    let {firstName}=req.body;
    let {lastName}=req.body;
    if(email && password){
        var result=await knex('users').select().where({email:email}).then(users => {return users[0]});
        if(result){
            return res.status(409).json({ "error": true,message:"User already exists"});
        }
        const saltRounds = 10;
        const hash =await bcrypt.hashSync(password, saltRounds);
        await knex('users').insert({
            email:email,
            password:hash
        })
        res.status(201).json({"message": "User created"});
    }else{
        res.status(400).json({ "error": true,"message": "Request body incomplete, both email and password are required"});
    }   
})

router.post('/login', async (req, res) => {
    let {email} =req.body;
    let {password} =req.body; 
    let {bearerExpiresInSeconds}=req.body; 
    let {refreshExpiresInSeconds}=req.body; 
    let {longExpiry}=req.body;
    if(email && password){
        var result=await knex('users').select().where({email:email}).then(users => {return users[0]});
        if(!result){
            return res.status(401).json({ "error": true,message:"Incorrect email or password"});
        }
       
        var bl=await bcrypt.compare(password,result.password);
        if(bl){
            var expires_in_bearer = 60 * 10;
            var expires_in_refresh =  60 * 60 * 24;
            if(longExpiry){
                expires_in_bearer= 60 * 60 * 24 * 365;
                expires_in_refresh=60 * 60 * 24 * 365;
            }else{
                if(bearerExpiresInSeconds){
                    expires_in_bearer=bearerExpiresInSeconds;
                }
                if(refreshExpiresInSeconds){
                    expires_in_refresh=refreshExpiresInSeconds;
                }
            }
            const exp_bearer = Math.floor(Date.now() / 1000) + expires_in_bearer;
            const token_bearer = jwt.sign({ email, exp_bearer }, process.env.JWT_SECRET);
            const exp_refresh = Math.floor(Date.now() / 1000) + expires_in_refresh;
            const token_refresh = jwt.sign({ email, exp_refresh }, process.env.JWT_SECRET);
            return res.status(200).json({
                "bearerToken":{
                    "token":token_bearer,
                    "token_type":"Bearer",
                    "expires_in":expires_in_bearer
                },
                "refreshToken":{
                    "token":token_refresh,
                    "token_type":"Refresh",
                    "expires_in":expires_in_refresh
                }
            });
        }else{
            return res.status(401).json({ "error": true,message:"Incorrect email or password"});
        }
    }else{
        res.status(400).json({ "error": true,"message": "Request body incomplete, both email and password are required"});
    }
});

router.post('/refresh',async (req, res) => {
    let {refreshToken}=req.body;
    if(!refreshToken){
        return res.status(400).json({ "error": true,"message": "Request body incomplete, refresh token required"})
    }
    try {
        var verify= jwt.verify(refreshToken, process.env.JWT_SECRET);
        var email=verify.email;
        var expires_in_bearer = 60 * 10;
        var expires_in_refresh =  60 * 60 * 24;
        const exp_bearer = Math.floor(Date.now() / 1000) + expires_in_bearer;
        const token_bearer = jwt.sign({ email, exp_bearer }, process.env.JWT_SECRET);
        const exp_refresh = Math.floor(Date.now() / 1000) + expires_in_refresh;
        const token_refresh = jwt.sign({ email, exp_refresh }, process.env.JWT_SECRET);
        console.log(email);
        return res.status(200).json({
            "bearerToken":{
                "token":token_bearer,
                "token_type":"Bearer",
                "expires_in":expires_in_bearer
            },
            "refreshToken":{
                "token":token_refresh,
                "token_type":"Refresh",
                "expires_in":expires_in_refresh
            }
        });
    } catch (e) {
        res.status(401).json({ error: true, message: "JWT token has expired" });
        return;
    }
});


router.post('/logout',async (req, res) => {
    let {refreshToken}=req.body;
    if(!refreshToken){
        return  res.status(400).json({ error: false, message: "Token successfully invalidated" });
    }
    try{
        var verify= jwt.verify(refreshToken, process.env.JWT_SECRET);
        res.status(200).json({ error: false, message: "JWT token has expired" });
    }catch(e){
        res.status(401).json({ error: true, message: "JWT token has expired" });
        return;
    }
});


router.get('/:email/profile',async (req, res) => {
    var {email}=req.params;
    var anuthorization=req.headers.authorization;
    if(anuthorization){
        if(!email){
            return res.status(404).json({ error: true, message: "User not found" });
        }
        var result=await knex('users').select().where({email:email}).then(users => {return users[0]});
        if(!result){
            return res.status(404).json({ error: true, message: "User not found" });
        }
        if (!("authorization" in req.headers)
        || !req.headers.authorization.match(/^Bearer /)
        ) {
            res.status(401).json({ error: true, message: "Authorization header ('Bearer token') not found" });
            return;
        }
        const token = req.headers.authorization.replace(/^Bearer /, "");
        try {
            var user=jwt.verify(token, process.env.JWT_SECRET);
            if(user.email==email){
               return res.status(200).json({email:result.email,firstName:result.firstName,lastName:result.lastName,dob:result.dob,address:result.address});
            }
        } catch (e) {
            if (e.name === "TokenExpiredError") {
                res.status(401).json({ error: true, message: "JWT token has expired" });
            } else {
                res.status(401).json({ error: true, message: "Invalid JWT token" });
            }
            return;
        }
        res.status(200).json({email:result.email,firstName:result.firstName,lastName:result.lastName});

    }else{
        if(!email){
            return res.status(404).json({ error: true, message: "User not found" });
        }
        var result=await knex('users').select().where({email:email}).then(users => {return users[0]});
        if(!result){
            return res.status(404).json({ error: true, message: "User not found" });
        }
        res.status(200).json({ email:result.email,firstName:result.firstName,lastName:result.lastName});
    }
});




router.put('/:email/profile',authorization,async (req, res) => {
    var {email}=req.params;
    var {firstName}=req.body;
    var {lastName}=req.body;
    var {dob}=req.body;
    var {address}=req.body;
    if(!email){
        return res.status(404).json({ error: true, message: "User not found" });
    }
    var result=await knex('users').select().where({email:email}).then(users => {return users[0]});
    if(!result){
        return res.status(404).json({ error: true, message: "User not found" });
    }
    const token = req.headers.authorization.replace(/^Bearer /, "");
    try {
        var user=jwt.verify(token, process.env.JWT_SECRET);
        if(user.email!=email){
            return res.status(403).json({ error: true, message: "Forbidden" }); 
        }
        if(!firstName || !lastName || !dob || !address){
            return res.status(400).json({ error: true, message: "Request body incomplete:firstName,lastName,dob and address are required" });
        }
        if(typeof(firstName)!='string' || typeof(lastName)!='string'  || typeof(dob)!='string'  || typeof(address)!='string' ){
            return res.status(400).json({ error: true, message: "Request body invalid:firstName,lastName,dob and address must be strings only" });
        }
        let reg = /^(?:(?!0000)[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|1[0-9]|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02]-31)|(?:[0-9]{2}(?:0[48]|[2468][048]|[1359][26])|(?:0[48]|[2468][048]|[1359][26])00)-02-29)$/;
        if(!reg.test(dob)){
            return res.status(400).json({ error: true, message: "Invalid input:dob must be a real date in format YYYY-MM-DD" });
        }
        var update=await knex('users').update({
            firstName:firstName,
            lastName:lastName,
            dob:dob,
            address:address
        }).where({email:email}).then(result => {return result});
        var now_result=await knex('users').select().where({email:email}).then(users => {return users[0]});
        res.status(200).json({email:now_result.email,firstName:now_result.firstName,lastName:now_result.lastName,dob:now_result.dob,address:now_result.address});
    } catch (e) {
        if (e.name === "TokenExpiredError") {
            res.status(401).json({ error: true, message: "JWT token has expired" });
        } else {
            res.status(401).json({ error: true, message: "Invalid JWT token" });
        }
        return;
    }
})


module.exports = router