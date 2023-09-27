import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import { IMongoDBUser } from "./types";
import User from "./User";
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const GitHubStrategy = require("passport-github").Strategy;

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
app.set("trust proxy", 1);
app.use(express.json());
app.use(cors({ origin: `${process.env.URL_FRONT}`, credentials: true }));
app.use(
  session({
    secret: "secretcode",
    resave: true,
    saveUninitialized: true,
    cookie: {
      sameSite: true,
      secure: true,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user: IMongoDBUser, done: any) => {
  return done(null, user._id);
});

passport.deserializeUser((id: String, done: any) => {
  User.findById(id)
    .exec()
    .then((doc: IMongoDBUser | any) => {
      if (!doc) {
        return done(null, false); // User not found
      }
      return done(null, doc);
    })
    .catch((err: Error) => {
      return done(err);
    });
});

// Strategies
passport.use(
  new GoogleStrategy(
    {
      clientID: `${process.env.GOOGLE_CLIENT_ID}`,
      clientSecret: `${process.env.GOOGLE_CLIENT_SECRET}`,
      callbackURL: "/auth/google/callback",
    },
    async function (_: any, __: any, profile: any, cb: any) {
      try {
        let user: any = await User.findOne({ googleId: profile.id });

        if (!user) {
          const newUserData: IMongoDBUser | any = {
            googleId: profile.id,
            username: profile.name.givenName,
          };

          const newUser = new User(newUserData);

          await newUser.save();

          user = newUserData; // Cast newUserData to IMongoDBUser
        }

        cb(null, user);
      } catch (err) {
        cb(err, null);
      }
    }
  )
);

passport.use(
  new TwitterStrategy(
    {
      consumerKey: `${process.env.TWITTER_APIKEY_ID}`,
      consumerSecret: `${process.env.TWITTER_APIKEY_SECRET}`,
      callbackURL: "/auth/twitter/callback",
    },
    async function (_: any, __: any, profile: any, cb: any) {
      try {
        let user: any = await User.findOne({ twitterId: profile.id });

        if (!user) {
          const newUserData: IMongoDBUser | any = {
            twitterId: profile.id,
            username: profile.username,
          };

          const newUser = new User(newUserData);

          await newUser.save();

          user = newUserData; // Cast newUserData to IMongoDBUser
        }

        cb(null, user);
      } catch (err) {
        cb(err, null);
      }
    }
  )
);

passport.use(
  new GitHubStrategy(
    {
      clientID: `${process.env.GITHUB_CLIENT_ID}`,
      clientSecret: `${process.env.GITHUB_CLIENT_SECRET}`,
      callbackURL: "/auth/github/callback",
    },
    async function (_: any, __: any, profile: any, cb: any) {
      try {
        let user: any = await User.findOne({ githubId: profile.id });

        if (!user) {
          const newUserData: IMongoDBUser | any = {
            githubId: profile.id,
            username: profile.username,
          };

          const newUser = new User(newUserData);

          await newUser.save();

          user = newUserData; // Cast newUserData to IMongoDBUser
        }

        cb(null, user);
      } catch (err) {
        cb(err, null);
      }
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
    failureRedirect: `${process.env.URL_FRONT}/login`,
    session: true,
  }),
  function (req, res) {
    res.redirect(`${process.env.URL_FRONT}`);
  }
);

app.get("/auth/twitter", passport.authenticate("twitter"));

app.get(
  "/auth/twitter/callback",
  passport.authenticate("twitter", {
    failureRedirect: `${process.env.URL_FRONT}/login`,
    session: true,
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect(`${process.env.URL_FRONT}`);
  }
);

app.get("/auth/github", passport.authenticate("github"));

app.get(
  "/auth/github/callback",
  passport.authenticate("github", {
    failureRedirect: `${process.env.URL_FRONT}/login`,
    session: true,
  }),
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

app.get("/auth/logout", (req, res) => {
  if (req.user) {
    req.logout((err: any) => {
      if (err) {
        // Handle any potential errors
        res.status(500).send("Logout error");
      } else {
        res.send("done");
      }
    });
  }
});

app.listen(process.env.PORT || 4000, () => {
  console.log("Server Started");
});
