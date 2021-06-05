var express = require('express');
require('dotenv').config()
var router = express.Router();
var jwt = require('jsonwebtoken')

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('rauth here');
});

let refreshTokens = []

//refresh the token after expiring
router.post('/token', (req, res) => {
    const refreshTn = req.body.token
    if(refreshTn == null) return res.sendStatus(401)
    //check if the refresh token exist in db in my case checking in the array
    if(!refreshTokens.includes(refreshTn)) return res.sendStatus(401)

    //verify here the refresh key and generate the access key
    jwt.verify(refreshTn, process.env.REFRESH_TOKEN_SECRET_KEY, (err, data) => {
        if(err){
            let obj = {
                "err": err
            }
            return res.json(obj)
        }
        console.log(data);
        let accessToken = jwt.sign({data}, process.env.ACCESS_TOKEN_SECRET_KEY,{expiresIn: '25s'})
        res.json({
            "accessToken": accessToken,
        })
    })
})

//post dummy test
router.post('/post', verifyToken, (req, res) => {
    console.log(req.token);
    //verify token
    jwt.verify(req.token, process.env.ACCESS_TOKEN_SECRET_KEY, (err, data) => {
        if(err) {
            res.sendStatus(403)
        }else{
            res.json({
                "message": "post created",
                data
            })
        }
    })
})

//verify if the token is exist
function verifyToken(req, res, next) {

    let token = req.headers['token'];
    if(typeof token !== "undefined"){
        req.token = token
        next()
    }else{
        res.sendStatus(403)
    }
}

//login funtion it will create two keys one for access and another one to refresh the token
router.post('/login', (req, res) => {
    let user = {
        "id": 1,
        "username": "Nazeer",
        "email": "Nazeer@gmail.com"
    }
    //create two keys one for access and one for refresh the access token
    let accessToken = jwt.sign({user: user}, process.env.ACCESS_TOKEN_SECRET_KEY,{expiresIn: '25s'})
    let refreshToken = jwt.sign({user: user}, process.env.REFRESH_TOKEN_SECRET_KEY)
    refreshTokens.push(refreshToken)
    res.json({
        "accessToken": accessToken,
        "refreshToken": refreshToken
    })
})


router.post('/logout', (req,res) => {
    //delete refresh token from db when user logout
    refreshTokens = refreshTokens.filter(e => e !== req.body.token)
    res.sendStatus(204)
})

module.exports = router;
