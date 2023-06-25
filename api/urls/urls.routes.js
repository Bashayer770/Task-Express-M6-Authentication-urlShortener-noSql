const express = require("express");

const router = express.Router();

const { shorten, redirect, deleteUrl } = require("./urls.controllers");
router.post(
  "/shorten/",
  passport.authenticate("jwt", { session: false }),
  shorten
);
router.get("/:code", redirect);
router.delete("/:code", deleteUrl);

module.exports = router;
