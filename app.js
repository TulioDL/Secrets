//jshint esversion:6
require('dotenv').config();
const bodyParser = require('body-parser');
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption'); //dotenv encryption
// const md5 = require('md5'); //hash encryption
// const bcrypt = require('bcrypt');   //Salt and Hash
// const saltRounds = 10;
const session = require('express-session');   //for usin cookies to authenticate users
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy; //we gonna use the google auth as a passport strategy
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static("public"));
app.set("view engine", 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({

    email: String,
    password: String,
    googleId: String,    //added googleId so de DB doesn't create new users each time someone enters with google (findOrCreate)
    secret: String
});

userSchema.plugin(passportLocalMongoose); //This is going to salt and hash the passport
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']}); //dotenv encryption

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());   //passport-local-mogoose, to serialize or deserialize local users
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {     //this will work with locals an not locals (passport documentation)
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({            //all of this is explained in the passport documentation
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets", //the same uri we put on the google API dashboard
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo' //google+ deprecation sollution
},
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) { //in order to findOrCreate to work, we have to install mongoose-findorcreate, require it an add it as a plugin to our schema
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
    
    res.render("home");
});

app.get('/auth/google', 
    passport.authenticate('google', { scope: ['profile'] })
    );

app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect to secrets page
      res.redirect("/secrets");
    });

app.get("/register", function (req, res) {
    
    res.render("register");
});

app.get("/login", function (req, res) {
    
    res.render("login");
});

app.get("/secrets", function (req, res) {
    // if (req.isAuthenticated()){   //we donn't want to authenticate no more to enter the secret page, 
    //     res.render("secrets");    //we just want it to show all secrets posted
    // } else {
    //     res.redirect("/login");
    // }

    User.find({"secret": {$ne:null}}, function (err, foundUsers) {  //look for every user with non empty secret value (ne=nonequeal)
        if (err){
            console.log(err);
        } else {
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/logout", function (req, res) {
    req.logout();   //to eliminate the cookie and logout from the server
    res.redirect("/");
});

//when u update the server, the cookie is deleted

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    
    const submittedSecret = req.body.secret;

    console.log(req.user.id);

    User. findById(req.user.id, function (err, foundUser) {
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets"); //after submit and save the secret, er redirect to the previous page
                })
            }
        }
    })
})

app.post("/register", function (req, res) {

    // bcrypt.genSalt(saltRounds, function(err, salt) {    //commented 'bcrypt'
    //     bcrypt.hash(req.body.password, salt, function(err, hash) {
    //         const newUser = new User ({
    //             email: req.body.username,
    //             //password: md5(req.body.password) //hashing the password
    //             password: hash   //salted and hashing with bcrypt
    //         });
    //         newUser.save(function (err) {
    //             if(err){
    //                 console.log(err);
    //             }else{
    //                 res.render("secrets")
    //             }
    //         });
    //         if (err) console.log(err);
    //     });
    //     if (err) console.log(err);
    // });

    User.register({username: req.body.username}, req.body.password, function (err, user) {
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () { //Will authenticate the cookie 
                res.redirect("/secrets"); //in this case we need to create the secrets route
            })
        }
    })
});

app.post("/login", function (req, res) {
    // const username = req.body.username;
    // //const password = md5(req.body.password); //hashing the input to compare
    // const password = req.body.password; //salted and hashed (bcrypt)

    // User.findOne({email: username}, function (err, foundUser) {   //Commented 'bcrypt'
        
    //     if(err){
    //         console.log(err);
    //     }else{
    //         if (foundUser){
    //             bcrypt.compare(password, foundUser.password, function(err, result) {
    //                 // result == true
    //                 if (result===true) res.render("secrets");
    //                 if (err) console.log(err);
    //             });

    //         };
    //     };
    // });

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) { //a passport method to login and authenticate
        if(err){
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
        
    })

});


app.listen(3000, function () {
    console.log("Server started in port 3000.");
})