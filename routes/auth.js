var express = require('express');
require('dotenv').config()
var router = express.Router();
var jwt = require('jsonwebtoken')

const Logger = require("../logger")

const logger = new Logger()

/* GET users listing. */
router.get('/', function (req, res, next) {
    res.send('rauth here');
});

// logger register listener
logger.on("LoggedMessage", (args) => {
    console.log(args)
})


let refreshTokens = []

let userList = []

let posts = [
    {
        "image": "https://s3-us-west-2.amazonaws.com/prd-rteditorial/wp-content/uploads/2021/01/30155602/harry-potter-and-the-sorcerers-stone-700x380.jpg",
        "name": "Harry Potter",
        "city": "London"
    },
    {
        "image": "https://static01.nyt.com/images/2019/04/19/arts/18manwho1/merlin_153439065_4f784f3f-bef0-44dd-89c0-3c8f7a820f27-superJumbo.jpg",
        "name": "Don Quixote",
        "city": "Madrid"
    },
    {
        "image": "https://variety.com/wp-content/uploads/2022/01/Joan-of-Arc.jpg?w=1000",
        "name": "Joan of Arc",
        "city": "Paris"
    }
]

//refresh the token after expiring
router.post('/token', (req, res) => {
    const refreshTn = req.headers['token'];
    if (refreshTn == null) return res.sendStatus(401)
    //check if the refresh token exist in db in my case checking in the array
    if (!refreshTokens.includes(refreshTn)) return res.sendStatus(401)

    //verify here the refresh key and generate the access key
    jwt.verify(refreshTn, process.env.REFRESH_TOKEN_SECRET_KEY, (err, data) => {
        if (err) {
            let obj = {
                "err": err
            }
            return res.json(obj)
        }
        console.log(data);
        let accessToken = jwt.sign({ data }, process.env.ACCESS_TOKEN_SECRET_KEY, { expiresIn: '2min' })
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
        if (err) {
            console.log(err)
            res.sendStatus(403)
        } else {
            res.json({
                "message": "post created",
                data
            })
        }
    })
})

router.post('/signUp', (req, res) => {
    //verify token
    const { username, password } = req.body
    if (userList.find(e => e.username == username)) {
        res.status(400).json({
            "Error": "User already exists with this username"
        })
    }
    else {
        console.log(req)
        let user = {
            "id": userList.length + 1,
            "password": password,
            "username": username
        }
        userList.push(user);
        res.json({
            "Success": "User created successfully!"
        })
    }
})

router.post('/getAllUser', (req, res) => {
    //verify token
    res.json({
        "Users": userList
    })
})

router.post('/getPost', verifyToken, (req, res) => {
    //verify token
    res.json({
        "Posts": posts
    })
})

//verify if the token is exist
function verifyToken(req, res, next) {

    console.log(req.cookies)

    let { token } = req.cookies;
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET_KEY, (err, data) => {
        if (err) {
            console.log(err)
            res.sendStatus(403).json(err)
        } else {
            next()
        }
    })
}

function verifyUser(req, res, next) {
    const { username } = req.body
    if (userList.find(e => e.username == username)) {
        next()
    } else {
        res.status(404).json({
            "Error": "User not found"
        })
    }
}

//login funtion it will create two keys one for access and another one to refresh the token
router.post('/login', verifyUser, (req, res) => {
    const { username, password } = req.body
    let user = {
        "id": 1,
        "username": password,
        "email": username
    }
    //create two keys one for access and one for refresh the access token
    let accessToken = jwt.sign({ user: user }, process.env.ACCESS_TOKEN_SECRET_KEY, { expiresIn: '2min' })
    let refreshToken = jwt.sign({ user: user }, process.env.REFRESH_TOKEN_SECRET_KEY)
    refreshTokens.push(refreshToken)
    logger.log("Logged in Successfully")
    res.status(202).cookie("token", accessToken, {
        sameSite: 'strict',
        path: '/',
        expires: new Date(new Date().getTime() + 5 * 10000),
        httpOnly: true,
        secure: true
    }).cookie("refresh-token", refreshToken, {
        sameSite: 'strict',
        path: '/',
        expires: new Date(new Date().getTime() + 5 * 10000),
        httpOnly: true,
        secure: true
    }).json({
        "accessToken": accessToken,
        // "refreshToken": refreshToken
    })
})


router.post('/logout', (req, res) => {
    //delete refresh token from db when user logout
    refreshTokens = refreshTokens.filter(e => e !== req.headers['token'])
    res.sendStatus(204)
})

module.exports = router;
