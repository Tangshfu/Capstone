const expect = require('chai').expect;
let chai=require('chai');
let should=chai.should;
const axios=require("axios");
const {userInfo,token_ul,API_URL,token_false} =require("./test.util");

describe("test", async() => {

    it("Valid JWT authentication", async() => {
        const login=await axios({
            url:API_URL+"/login",
            method:"post",
            headers: {
                'content-type': 'application/x-www-form-urlencoded',
            },
            data:userInfo,
        });
        var token=login.data.token.token;
        const auth=await axios({
            url:API_URL+"/auth",
            method:"post",
            headers: {
                'content-type': 'application/x-www-form-urlencoded',
                "Authorization":"Bearer "+token,
            },
        });
        expect(auth.data.message).to.be.equal("Valid JWT authen.");
    });
    
    
    it("Expired JWT authentication", async() => {
        try{
            let token =await axios({
                url:API_URL+"/auth",
                method:"post",
                headers: {
                    'content-type': 'application/x-www-form-urlencoded',
                    "Authorization":"Bearer "+token_ul,
                },
            });
        }catch(e){
            console.log();
            expect(e.response.data.message).to.be.equal("Expired JWT authentication.");
        }
    });

    it("Invalid JWT token.", async() => {
        try{
            let token =await axios({
                url:API_URL+"/auth",
                method:"post",
                headers: {
                    'content-type': 'application/x-www-form-urlencoded',
                    "Authorization":"Bearer "+token_false,
                },
            });
        }catch(e){
            expect(e.response.data.message).to.be.equal("Invalid JWT token.");
        }
    });

    it("Expired JWT validation.", async() => {
            let token =await axios({
                url:API_URL+"/auth",
                method:"post",
                headers: {
                    'content-type': 'application/x-www-form-urlencoded',
                    "Authorization":"Bearer "+token_ul,
                },
                data:{
                    "expired":true
                },
            });
            expect(token.data.message).to.be.equal("Expired JWT validation.");
    });

    
})