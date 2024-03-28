const express = require("express");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const app = express();

app.use(express.json()); // to parse json into javascript/usable object
// app.use(cors()); //this will allow all origins, requests and headers;
// OR to use token based cookie need to spevify cors options specially credientials to true as below also in client side 
app.use(
    cors({
        origin: 'http://localhost:3000', // Specify the origin(s) you want to allow
        // methods: ['GET', 'POST'], // Specify the HTTP methods you want to allow
        // allowedHeaders: 'Content-Type,Authorization', // Specify allowed headers
        credentials: true //set this also in client side, else data won't stored in cookie
    })
);


app.use(cookieParser()); //to get the cookie "(sent from client using {withCrediential: true})" and make avaible in the req.cookies 
// app.use(express.urlencoded({ extended: true })) //parse form data bcz is application/x-www-form-urlencoded format. This middleware allows Express to parse that data and make it available in the req.body 


const port = 3002;

const users = [] //hard code instead of database

//hash user pass and add it in the list/database
app.post("/api/signUp", async (req, res) => {
    console.log("req.body", req.body);
    try {
        let { name, email, password } = req.body;
        let user = users.find((cur) => cur.email === email);
        if (user) {
            return res.status(409).json({ message: "User with this email already exists!" })
        }
        let hashedPassword = await bcrypt.hash(password, 10);
        users.push({ name: name, email: email, password: hashedPassword });
        console.log("users", users);
        res.status(201).json({ message: "User successfully created!" });
    } catch (err) {
        res.status(500).json({ message: "Internal server error" });
    }
});

//check user if exists, assign it a jwt

app.post('/api/signIn', async (req, res) => {
    const { email, password } = req.body;
    console.log("fined user above", req.body);

    try {
        const user = users.find((cur) => cur.email === email);
        console.log("fined user", user);
        if (!user) {
            return res.status(401).json({ message: "Email address not found" })
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Incorrect Password" });
        }
        const token = jwt.sign({ name: user.name, email: user.email }, "my_secret_key", { expiresIn: '1h' });
        console.log("token", token);

        // res.cookie('Token', token, { httpOnly: true, domain: '192.168.8.100', });
        res.cookie('Token', token, { maxAge: 60000, httpOnly: true }); // when httpOnly: true javascript cannot access cookie document.cookie 

        // res.cookie("test", 'thapa');


        res.status(200).json({ message: "Sign in successfull!", token: token }); //when using localstorage no need to send cookie above like OR
        // OR

    } catch (err) {
        res.status(500).json({ message: "Internal server error", error: err })
    }
})

const authorizationMiddleware = (req, res, next) => {
    try {
        // // const token = req.header("Authorization"); when token sent as header Authorization: "Bearer 2y345ylkh45..." also when localStorage used and not cookies 
        // const Token = token.replace("Bearer ", ""); //to remove space as token is sent as Bearer
        // console.log("token", token);
        // console.log("tokenWithOutBearer", tokenWithOutBearer);
        // // OR when token based cookie is used below

        console.log("req.cookies.Token", req.cookies.Token);
        const Token = req.cookies.Token;

        // now user can Unauthorized base on two ways below,

        // first: if req.cookies.Token is undefines because of maxAge: 60000 expires.
        if (!Token) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        // second: if jwt.verify will not verify because of EITHER token which is sent from client is changed then (Token, 'my_secret_key') denied OR  token is sent after 1h as { expiresIn: '1h' }.
        const decode = jwt.verify(Token, 'my_secret_key');
        console.log("decode", decode);
        req.user = decode;
        next();

    } catch (err) {
        res.status(500).json({ message: "Internal server error", error: err });
    }
}

app.get('/protected', authorizationMiddleware, (req, res) => {
    res.status(200).json({ message: "Authorized", user: req.user });
})


// just a simple example of how to send and store cookie if cors is used with options specially credientials to true as  cors({origin: 'http://localhost:3000', credentials: true}) and on client side {withCrediential: true} with axios get or post or put or delete methods
// app.get('/contact', (req, res) => {
//     res.cookie("test", 'thapa');
//     res.send('hello contant')
// })




app.listen(port, () => {
    console.log("Server is running on port=", port);
})