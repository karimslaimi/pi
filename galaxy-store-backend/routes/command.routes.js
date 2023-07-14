const express = require('express');
const router = express.Router();
const CommandeController = require('../controllers/command.controller');
const { authJwt } = require("../middleware");
const { isUser, isAdmin } = require('../middleware/authJwt.js');

router.post('/save',CommandeController.createCommandsForBits,[authJwt.verifyToken,isAdmin]);
router.get('/all',CommandeController.getAllCommandes,[authJwt.verifyToken,isAdmin]);
router.get('/allByUser',CommandeController.getCommandsByUserInBits,[authJwt.verifyToken,isUser]);
router.put('/update/:id',CommandeController.updateCommande,[authJwt.verifyToken,isAdmin]);
router.delete('/delete/:id',CommandeController.deleteCommande,[authJwt.verifyToken,isAdmin]);
router.get('/allprogressing',CommandeController.getAllCommandsProcessing,[authJwt.verifyToken,isAdmin]);
router.get('/allvalidated',CommandeController.getAllCommandsValidated,[authJwt.verifyToken,isAdmin]);
router.get('/allfactured',CommandeController.getAllCommandsFactured,[authJwt.verifyToken,isAdmin]);

module.exports = router;