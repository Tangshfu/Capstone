const express = require('express')
const router = express.Router()
const jwt = require('jsonwebtoken');
const jwks = require('jwks-rsa');
const jose = require('jose');
const fs = require('fs');

var NodeRSA = require('node-rsa');
var key = new NodeRSA({b: 512});//生成512位秘钥


function randomRangeld(num){
    var returnStr ="";
    charStr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnoparstuvwxyz0123456789';
    for(var i=0; i<num; i++){
        var index = Math.round(Math.random() *(charStr.length- 1));
        returnStr += charStr.substring(index,index+ 1);
    }
    return returnStr;
}



//登录，然后token生成
router.post('/login',async (req, res) => {
    let {username} =req.body;
    let {password} =req.body; 
    if(username && password){
        const publicKey = key.exportKey('public');
        const privateKey = key.exportKey('private');
        // var encrypted = pubkeys.encrypt("buffer", 'base64');
        // var buffer=Buffer.from("", 'base64');
        // var decrypted = priKey.decrypt(buffer, 'utf8');
        
        // const time = Math.floor(Date.now() / 1000) + expires_in_bearer;
        //过期时间
        var token_time_stap = 60;
        var jwk_time_stap=60*10*2;
        var curTime=new Date();
        var time=new Date(curTime.setSeconds(curTime.getSeconds() + jwk_time_stap));
        const algorithm = 'ES256';
        const ecPublicKey = await jose.importSPKI(publicKey, algorithm);
        let jwk = await jose.exportJWK(ecPublicKey);
        var kid=randomRangeld(30);
        jwk={
            ...jwk,
            "kid":kid,
            "time":time
        };

        await fzJWK(jwk);
        let now_data=jwt.sign({ "kid":kid,"username":username,"password":password},publicKey.split("\n")[1]+publicKey.split("\n")[2], { expiresIn: token_time_stap+'s',algorithm:"HS256" });
        time=new Date(curTime.setSeconds(curTime.getSeconds() + token_time_stap));
        return res.status(200).json({
            "token":{
                "token":now_data,
                "time":time,
                "jwk":jwk
            }
        });
    }else{
        res.status(400).json({ "error": true,"message": "Request body incomplete, both username and password are required"});
    }
});

//封装jwk.json
async function fzJWK(json){
    var path="./static/jwks.json";
    fs.readFile(path,function(err,data){
        if(err){
            console.log(err);
        }else{
            let jwks=data.toString();
            //console.log(jwks);
            jwks=JSON.parse(jwks);	
            let now_jsks={"keys":[]};
            if(jwks.keys){
                now_jsks=jwks
            }
            now_jsks.keys.push(json);
            let new_jwks=JSON.stringify(now_jsks);
            fs.writeFile(path,new_jwks,function(err){});
        }
    });
}

//验证token
router.post('/auth',async (req, res) => {
    if (!("authorization" in req.headers)
        || !req.headers.authorization.match(/^Bearer /)
    ) {
        res.status(401).json({ error: true, message: "Authorization header ('Bearer token') not found" });
        return;
    }
    const token = req.headers.authorization.replace(/^Bearer /, "");
    try {
        const client = jwks({
            jwksUri: 'http://localhost:8080/jwks.json',
            requestHeaders: {}, // Optional
            timeout: 30000 // Defaults to 30s
        });
        var decoded = jwt.decode(token, {complete: true});
        var key=decoded.payload.kid;
        client.getSigningKey(key, (error, key) => {
            if (error){
                res.status(400).send({error: true,"message":"Expired JWK Not Found In JWKS."});
            }
            const signingKey = key.publicKey || key.rsaPublicKey;
            var {expired}=req.body;
            try {
                jwt.verify(token, signingKey.split("\n")[1]+signingKey.split("\n")[2],{ algorithms: 'HS256' },(err,data)=>{
                    if(err){
                        if(expired){
                            return res.status(200).json({
                                "message":"Expired JWT validation.",
                                "verified":decoded.payload
                            });
                        }else{
                            return res.status(400).send({error: true, message: "Expired JWT authentication." });
                        }
                    }
                    return res.status(200).json({
                        "message":"Valid JWT authen.",
                        "verified":data
                    });
                });
            } catch (error) {
                return res.status(400).send({ message: error.message, stack: error.stack })
            }
        })
    } catch (e) {
        if (e.name === "TokenExpiredError") {
            return  res.status(401).json({ error: true, message: "Expired JWT authentication." });
        } else {
            return  res.status(401).json({ error: true, message: "Invalid JWT token." });
        }
        //Expired JWT authentication
        return;
    }
});

module.exports = router;