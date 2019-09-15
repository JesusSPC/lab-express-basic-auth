const express = require("express");
const router = express.Router();
const Users = require("../models/Users");
const bcrypt = require("bcrypt");

router.get("/signup", (req, res) => {
  if (req.query.error) {
    if (req.query.error === "empty") {
      res.render("signup", {
        error: "The provided username and/or password were empty"
      });
    }

    if (req.query.error === "user-exists") {
      res.render("signup", { error: "The provided username already exists" });
    }
  } else {
    res.render("signup");
  }
});

router.post("/signup", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username.length === 0 || password.length === 0) {
    res.redirect("/signup?error=empty");
  }

  Users.findOne({ username: username }).then(foundUserData => {
    if (foundUserData === null) {
      const saltRounds = 10;

      const salt = bcrypt.genSaltSync(saltRounds);
      const encryptedPassword = bcrypt.hashSync(password, salt);

      Users.create({ username: username, password: encryptedPassword }).then(
        userData => {
          res.json({ userCreated: true, userData });
        }
      );
    } else {
      res.redirect("/signup?error=user-exists");
    }
  });
});

router.get("/login", (req, res) => {
  if (req.query.error) {
    if (req.query.error === "empty") {
      res.render("login", {
        error: "The provided username and/or password were empty"
      });
    }

    if (req.query.error === "user-doesnot-exist") {
      res.render("login", { error: "The provided username does not exists!" });
    }

    if (req.query.error === "password-wrong") {
      res.render("login", {
        error: "The provided password is incorrect. Please try again."
      });
    }
  } else {
    res.render("login");
  }
});

router.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username.length === 0 || password.length === 0) {
    res.redirect("/login?error=empty");
  }

  Users.findOne({ username: username }).then(foundedData => {
    if (foundedData === null) {
      res.redirect("/login?error=user-doesnot-exist");
    } else {
      const hashedPass = foundedData.password;
      if (bcrypt.compareSync(password, hashedPass)) {
        req.session.user = foundedData._id;
        res.redirect("/");
      } else {
        res.redirect("/login?error=wrong-password");
      }
    }
  });
});

// router.get("/home", (req, res) => {
//   if (req.session.user) {
//     Users.findById(req.session.user).then(data => {
//       res.render("home", { userData: data });
//     });
//   } else {
//     res.redirect("/login");
//   }
// });

module.exports = router;
