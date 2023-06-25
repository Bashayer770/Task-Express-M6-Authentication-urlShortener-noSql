const connectDb = require("./database");
const express = require("express");
const { localStrategy, JWTStrategy } = require("./middleware/passport");
const app = express();
const urlRoutes = require("./api/urls/urls.routes");
const userRoutes = require("./api/users/users.routes");
const passport = require("passport");

connectDb();
app.use(express.json());

app.use("/urls", urlRoutes);
app.use(userRoutes);
app.use(passport.initialize());
passport.use(localStrategy);
passport.use.apply(JWTStrategy);

app.use((req, res, next) => {
  const err = new Error("Not Found");
  err.status = 404;
  next(err);
});

app.use((err, req, res, next) => {
  res.status(err.status || 500);
  res.json({
    error: {
      message: err.message || "Internal Server Error",
    },
  });
});

app.listen(8000, () => {
  console.log("The application is running on localhost:8000");
});
