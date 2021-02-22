//jshint esversion:6
require('dotenv').config();
const bodyParser = require('body-parser');
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption'); //dotenv encryption
// const md5 = require('md5'); //hash encryption
const bcrypt = require('bcrypt');

const saltRounds = 10;
const app = express();

app.use(express.static("public"));
app.set("view engine", 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({

    email: String,
    password: String
});


// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']}); //dotenv encryption

const User = new mongoose.model("User", userSchema);

app.get("/", function (req, res) {
    
    res.render("home");
});

app.get("/register", function (req, res) {
    
    res.render("register");
});

app.get("/login", function (req, res) {
    
    res.render("login");
});

app.post("/register", function (req, res) {

    bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(req.body.password, salt, function(err, hash) {
            const newUser = new User ({
                email: req.body.username,
                //password: md5(req.body.password) //hashing the password
                password: hash   //salted and hashing with bcrypt
            });
            newUser.save(function (err) {
                if(err){
                    console.log(err);
                }else{
                    res.render("secrets")
                }
            });
            if (err) console.log(err);
        });
        if (err) console.log(err);
    });
});

app.post("/login", function (req, res) {
    const username = req.body.username;
    //const password = md5(req.body.password); //hashing the input to compare
    const password = req.body.password; //salted and hashed (bcrypt)

    User.findOne({email: username}, function (err, foundUser) {
        
        if(err){
            console.log(err);
        }else{
            if (foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    // result == true
                    if (result===true) res.render("secrets");
                    if (err) console.log(err);
                });

            };
        };
    });
});

app.listen(3000, function () {
    console.log("Server started in port 3000.");
})