import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";   // Local strategy to authenticate user
import GoogleStrategy from "passport-google-oath2";  // Google authentication strategy
import session from "express-session";
import env from "dotenv"; 

const app = express();
const port = 3000;
const saltRounds = 10;   // salt rounds for additional layer of security
env.config();  // Environment variable configuration

// passport session configuration. Acts as middleware to some extent.
app.use(session({
  secret: "TOPSECTRETWORD",
  resave: false,
  saveUninitialized: true,
  })
);

// Normal middleware from body parser
app.use(bodyParser.urlencoded({ extended: true }));
// Something about using static files for stylig and rendering
app.use(express.static("public"));

// Initialization of passport and then the passport session directly after and never session before init. Syustem will crash
app.use(passport.initialize());
app.use(passport.session()); 




// pg configuration
const db = new pg.Client({
  user: "process.env.PG_USER",
  host: "process.env.PG_HOST",
  database: "process.env.PG_DATABASE",
  password: "process.env.PG_PASSWORD",
  port: "process.env.PG_PORT",
  cookie: {
    maxAge: 1000 * 60 * 15,      // Trying to have a session age of 15 mins instead of 24 hours
  }
});
db.connect();





// These are all the default routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // This is the use of postgres database query wrapping the SQL code into a javascript member funtion.
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and adding the unique salt to it. function either returns an err or a hash. Based on this you can check for either or that exists
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secfets"); 
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failRedirect: "/login",
}));
// End of default routes ///////////////////////////////////////////////////////////////////////////

// Authenticated cookie routes
app.get("/secrets", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()){                // in the req there is a boolean called isAuthenticated and we check for it.
    res.render("secrets.ejs");
  } else {
    res.redirect("/login"); 
  }
}); 

app.get("/auth/google",                       // oauth/login get route 
  passport.authenticate ("google", {
    scope: ["profile", "email"],
  })
);


app.get("/auth/google/secrets",              // Get method for after the oauth login
  passport.authenticate ("google", {
    successRedirect: "/secrets", 
    failureRedirect:"login", 
})); 






// The actual use & implimentation of the local strategy authentication. 
passport.use("local", new Strategy(async function verify(username, password, cb){
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(loginPassword, storedHashedPassword, (err, result) => {
        if (err) {
          return cd(err);
        } else {
          if (result) {
            return cb(null, user);
          } else {
            return cb("User not found")
          }
        }
      });
    } else {
      return cb("User not found");
    }
  } catch (err) {
    return cb(err);
  }
}));

// Configuration of the google authentication strategy.
passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET, 
  callbackURL: "http://localhost3000/auth/google/secrets",
  userProfileURL: "http://www.googleapis.com/oauth/v3/userinfo",
}), async (accessToken, refreshToken, profile, cb) => {
  console.log(profile);
}); 


// Passport's serializeUser function is responsible for deciding what part of the user object gets stored in the session. 
// Here, we're storing the entire user object in the session.
passport.serializeUser((user, cb) => {
  cb(null, user); 
}); 

passport.deserializeUser((user, cb) =>{
  cb(null, user); 
}); 

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
