const express = require('express');
const router = express.Router();
const PaymentController = require('../controllers/payment.controller');
const { authJwt } = require("../middleware");
const { isUser, isAdmin } = require('../middleware/authJwt.js');

router.post('/pay/:idFacture',PaymentController.payFacture,[authJwt.verifyToken,isUser]);

module.exports = router;