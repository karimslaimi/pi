const express = require('express');
const router = express.Router();
const FactureController = require('../controllers/facture.controller');
const { authJwt } = require("../middleware");
const { isAdmin } = require('../middleware/authJwt.js');

router.get('/:commandeId', FactureController.generateFacture,[authJwt.verifyToken,isAdmin]);
module.exports = router;
