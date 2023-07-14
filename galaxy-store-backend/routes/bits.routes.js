const express = require('express');
const router = express.Router();
const BitsController = require('../controllers/bits.controller.js');
const { authJwt } = require("../middleware");
const { isUser, isAdmin } = require('../middleware/authJwt.js');

router.post('/save',BitsController.createBits,[authJwt.verifyToken,isUser]);
router.get('/all',BitsController.getAllBits,[authJwt.verifyToken,isAdmin]);
router.get('/allByUser',BitsController.getUserConnectedBits,[authJwt.verifyToken,isUser]);
router.get('/allclosedBits',BitsController.getAllClosedBits,[authJwt.verifyToken,isAdmin]);
router.get('/allinprogressBits',BitsController.getAllInProgressBits,[authJwt.verifyToken,isAdmin]);
router.get('/allclosedBitsByUser',BitsController.getAllClosedBitsByUserConnected,[authJwt.verifyToken,isUser]);
router.get('/allinprogressByUser',BitsController.getAllProgressBitsByUserConnected,[authJwt.verifyToken,isUser]);
router.delete('/deleteBit/:bitId',BitsController.deleteBit,[authJwt.verifyToken,isUser])
router.get('/:id',BitsController.getBitById,[authJwt.verifyToken,isAdmin]);
router.get('/byUser/:id',BitsController.getBitByIdAndIdUser,[authJwt.verifyToken,isUser]);
router.get('/history/:productId',BitsController.getBitsByProduct,[authJwt.verifyToken,isUser]);

module.exports = router;
