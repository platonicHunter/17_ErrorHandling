const crypto = require("crypto");
//for password
const bcrypt = require("bcryptjs");

//mail
const { sendResetEmail } = require("../models/sendMail");

const User = require("../models/user");
const user = require("../models/user");

exports.getLogin = (req, res, next) => {
  const errorMessage = req.flash("error")[0] || null;
  const successMessage = req.flash("success")[0] || null;

  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: errorMessage,
    successMessage: successMessage,
  });
};

exports.getSignup = (req, res, next) => {
  const errorMessage = req.flash("errorSign")[0] || null;
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Sign Up",
    errorMessage: errorMessage,
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        req.flash("error", "Invalid email or password");
        return res.redirect("/login");
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect("/");
            });
          }
          req.flash("error", "Invalid  password");
          res.redirect("/login");
        })
        .catch((err) => {
          console.log(err);
          res.redirect("./login");
        });
    })
    .catch((err) => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  if (password !== confirmPassword) {
    req.flash("errorSign", "Passwords do not match");
    return res.redirect("./signup");
  }

  User.findOne({ email: email })
    .then((userDoc) => {
      if (userDoc) {
        req.flash("errorSign", "Email has Created.Join Another");
        return res.redirect("./signup");
      }
      return bcrypt
        .hash(password, 12)
        .then((hashPassword) => {
          const user = new User({
            email: email,
            password: hashPassword,
            cart: { items: [] },
          });
          return user.save();
        })
        .then((result) => {
          req.flash("success", "Successfully!Email has Created");
          res.redirect("./login");
        });
    })
    .catch((err) => console.log(err));
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect("/");
  });
};

//reset

exports.getReset = (req, res, next) => {
  const errorMessage = req.flash("errorReset")[0] || null;
  const successMessage = req.flash("successReset")[0] || null;
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: errorMessage,
    successMessage: successMessage,
  });
};

exports.postReset = (req, res, next) => {
  const { email } = req.body;

  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.error("Error generating random bytes:", err);
      req.flash("errorReset", "Something went wrong, please try again.");
      return res.redirect("/reset");
    }

    const token = buffer.toString("hex");

    User.findOne({ email: email })
      .then((user) => {
        if (!user) {
          req.flash("errorReset", "No account with that email found.");
          return res.redirect("/reset");
        }

        // Update user document with reset token and expiration
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000; // 1 hour in milliseconds

        return user.save().then((result) => {
          // Send email with reset token
          const emailSent = sendResetEmail(email, token);

          if (emailSent) {
            req.flash("successReset", "Look in your email");
            return res.redirect("/reset");
          } else {
            req.flash("errorReset", "Email not sent.");
            return res.redirect("/reset");
          }
        });
      })
      .catch((err) => {
        console.error("Error in password reset:", err);
        req.flash("errorReset", "Something went wrong, please try again.");
        res.redirect("/reset");
      });
  });
};

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
    .then((user) => {
      if (!user) {
        req.flash(
          "errorReset",
          "Password reset token is invalid or has expired."
        );
        return res.redirect("/reset");
      }

      const errorMessage = req.flash("errorNP")[0] || null;
      const successMessage = req.flash("successNP")[0] || null;

      res.render("auth/new-password", {
        path: "/new-password",
        pageTitle: "New Password",
        errorMessage: errorMessage,
        successMessage: successMessage,
        userId: user._id.toString(),
        passwordToken: token,
      });
    })
    .catch((err) => {
      console.error("Error fetching user with reset token:", err);
      req.flash("errorReset", "Something went wrong, please try again.");
      res.redirect("/reset");
    });
};


exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const newConfirmPassword = req.body.confirmPassword;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  if (newPassword !== newConfirmPassword) {
    console.log('password not match')
    req.flash("errorNP", "Passwords do not match.");
    return res.redirect(`/reset/${passwordToken}`);
    
  }

  User.findOne({
    resetToken: passwordToken,
    resetTokenExpiration: { $gt: Date.now() },
    _id: userId,
  })
    .then((user) => {
      if (!user) {
        req.flash('errorReset', 'Password reset token is invalid or has expired.');
        return res.redirect('/reset');
      }
      resetUser = user;
      return bcrypt.hash(newPassword, 12);
    })
    .then((hashPassword) => {
      resetUser.password = hashPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then(() => {
      req.flash("success", "Password changed successfully.");
      res.redirect('/login');
    })
    .catch((err) => {
      console.log(err);
      req.flash("errorNP", "Something went wrong, please try again.");
      res.redirect(`/reset/${passwordToken}`);
    });
};
