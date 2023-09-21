import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import session from "express-session";
import passport from "passport";
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;

dotenv.config();

const app = express();

// Connect to MongoDB using async/await
async function connectToDatabase() {
  try {
    await mongoose.connect(`${process.env.MDB_CONNECT}`, {});
    console.log("Connected to Mongoose Successfully");
  } catch (error) {
    console.error(error);
  }
}

// Call the connectToDatabase function to connect to MongoDB
connectToDatabase();

//Middleware
app.use(express.json());
app.use(cors({ origin: `${process.env.URL_FRONT}`, credentials: true }));
app.use(
  session({
    secret: "secretcode",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user: any, done: any) => {
  return done(null, user);
});

passport.deserializeUser((user: any, done: any) => {
  return done(null, user);
});

passport.use(
  new GoogleStrategy(
    {
      clientID: `${process.env.GOOGLE_CLIENT_ID}`,
      clientSecret: `${process.env.GOOGLE_CLIENT_SECRET}`,
      callbackURL: "/auth/google/callback",
    },
    function (accessToken: any, refreshToken: any, profile: any, cb: any) {
      // console.log(profile);
      cb(null, profile);
    }
  )
);

passport.use(
  new TwitterStrategy(
    {
      consumerKey: `${process.env.TWITTER_CLIENT_ID}`,
      consumerSecret: `${process.env.TWITTER_CLIENT_SECRET}`,
      callbackURL: "/auth/twitter/callback",
    },
    function (accessToken: any, refreshToken: any, profile: any, cb: any) {
      // console.log(profile);
      cb(null, profile);
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: `${process.env.URL_FRONT}`,
    session: true,
  }),
  function (req, res) {
    res.redirect(`${process.env.URL_FRONT}`);
  }
);

app.get("/auth/twitter", passport.authenticate("twitter"));

app.get(
  "/auth/twitter/callback",
  passport.authenticate("twitter", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect(`${process.env.URL_FRONT}`);
  }
);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.get("/getuser", (req, res) => {
  res.send(req.user);
});

app.listen(4000, () => {
  console.log("Server Started");
});
