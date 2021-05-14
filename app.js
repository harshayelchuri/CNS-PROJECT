 //jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//////////////////////////elgamalcode starting/////////////////////////////////////

var Alphabet = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ \nπ®ƒ©∆";

Alphabet = Alphabet.split("");

var Crypto = function (alpha, gen, C) {
    var p, B, encrypt, decrypt, f, g, modInv, modPow, toAlpha, to10;
    toAlpha = function (x) {
        var y, p, l, n;
        if (x === 0) {
            return "!!!!";
        }
        y = [];
        n = 4;
        n = Math.ceil(n);
        while (n--) {
            p = Math.pow(alpha.length, n);
            l = Math.floor(x / p);
            y.push(alpha[l]);
            x -= l * p;
        }
        y = y.join("");
        return y;
    };
    to10 = function (x) {
        var y, p, n;
        y = 0;
        p = 1;
        x = x.split("");
        n = x.length;
        while (n--) {
            y += alpha.indexOf(x[n]) * p;
            p *= alpha.length;
        }
        return y;
    };
    modInv = function (gen, mod) {
        var v, d, u, t, c, q;
        v = 1;
        d = gen;
        t = 1;
        c = mod % gen;
        u = Math.floor(mod / gen);
        while (d > 1) {
            q = Math.floor(d / c);
            d = d % c;
            v = v + q * u;
            if (d) {
                q = Math.floor(c / d);
                c = c % d;
                u = u + q * v;
            }
        }
        return d ? v : mod - u;
    };
    modPow = function (base, exp, mod) {
        var c, x;
        if (exp === 0) {
            return 1;
        } else if (exp < 0) {
            exp = -exp;
            base = modInv(base, mod);
        }
        c = 1;
        while (exp > 0) {
            if (exp % 2 === 0) {
                base = (base * base) % mod;
                exp /= 2;
            } else {
                c = (c * base) % mod;
                exp--;
            }
        }
        return c;
    };
    p = 91744613;
    C = parseInt(C, 10);
    if (isNaN(C)) {
        C = Math.round(Math.sqrt(Math.random() * Math.random()) * (p - 2) + 2);
    }
    B = modPow(gen, C, p);
    decrypt = function (a) {
        var d, x, y;
        x = a[1];
        y = modPow(a[0], -C, p);
        d = (x * y) % p;
        d = Math.round(d) % p;
        return alpha[d - 2];
    };
    encrypt = function (key, d) {
        var k, a;
        k = Math.ceil(Math.sqrt(Math.random() * Math.random()) * 1E10);
        d = alpha.indexOf(d) + 2;
        a = [];
        a[0] = modPow(key[1], k, key[0]);
        a[1] = (d * modPow(key[2], k, key[0])) % key[0];
        return a;
    };
    f = function (message, key) {
        var n, x, y, w;
        y = [];
        message = message.split("");
        n = message.length;
        while (n--) {
            x = encrypt(key, message[n]);
            y.push(toAlpha(x[0]));
            y.push(toAlpha(x[1]));
        }
        y = y.join("");
        return y;
    };
    g = function (message) {
        var n, m, d, x;
        m = [];
        n = message.length / 8;
        while (n--) {
            x = message[8 * n + 4];
            x += message[8 * n + 5];
            x += message[8 * n + 6];
            x += message[8 * n + 7];
            m.unshift(x);
            x = message[8 * n];
            x += message[8 * n + 1];
            x += message[8 * n + 2];
            x += message[8 * n + 3];
            m.unshift(x);
        }
        x = [];
        d = [];
        n = m.length / 2;
        while (n--) {
            x[0] = m[2 * n];
            x[1] = m[2 * n + 1];
            x[0] = to10(x[0]);
            x[1] = to10(x[1]);
            d.push(decrypt(x));
        }
        message = d.join("");
        return message;
    };
    return {
        pubKey: [p, gen, B],
        priKey: C,
        decrypt: g,
        encrypt: f
    };
};

// Usage:

var Alice = Crypto(Alphabet, 69);

var Bob = Crypto(Alphabet, 69);

var emessage = "";
var dmessage = "";

// "Hello!"

// message = Alice.encrypt(message, Bob.pubKey);
// // "Pl)7t&rfGueuL@|)H'P,*<K\.hxw+∆d*`?Io)lg~Adz-6xrR" or something like it.
//
// dmessage = Bob.decrypt(message);

/////////////////////////// elgamal code ending ///////////////////////////////

app.get("/", function(req, res){
  res.render("home");
});


app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  emessage='';
  dmessage='';
  if (req.isAuthenticated()){
    res.render("secrets");
  } else{
    emessage='';
    dmessage='';
    res.redirect("/login");
  }
});

app.get("/encrypt", function(req, res){
  if (req.isAuthenticated()){
    res.render("encrypt",{
      emessage:emessage
    });
  } else{
    res.redirect("/login");
  }
});

app.get("/decrypt", function(req, res){
  if (req.isAuthenticated()){
    res.render("decrypt",{
      dmessage:dmessage
    });
  } else{
    res.redirect("/login");
  }
});


app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/encrypt",function(req, res){
  message=req.body.message
  emessage = Alice.encrypt(message, Bob.pubKey);
  res.render("encrypt.ejs",{
    emessage:emessage
  });
});

app.post("/decrypt",function(req, res){
  message=req.body.message
  dmessage = Bob.decrypt(message);
  res.render("decrypt.ejs",{
    dmessage:dmessage
  });
});



app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
