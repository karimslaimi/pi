const express = require('express');
const { authJwt } = require("../middleware");
const router = express.Router();
const socialMediaController = require("../controllers/socialMedia.controller");
const { isAdmin } = require('../middleware/authJwt.js');

router.post('/', socialMediaController.getSocialMediaLinks, [authJwt.verifyToken, isAdmin]);


module.exports = router;