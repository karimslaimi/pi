const express = require('express');
const ClaimController = require('../controllers/claim.controller');
const validObjectId = require('../middleware/validObjectId');
const isAuth = require('../middleware/isAuth');
const multer = require('../middleware/uploadImage');
const router = express.Router();


router.get('/', [isAuth], ClaimController.getAllClaims);
router.post('/', [isAuth, multer.single('image')], ClaimController.createClaim);
router.delete('/:id', [isAuth, validObjectId], ClaimController.deleteClaim);
router.put('/:id', [isAuth, validObjectId], ClaimController.updateClaim);
router.get('/user/:userId', [isAuth], ClaimController.getClaimsByUserId);
router.get('/status/:status', [isAuth], ClaimController.getClaimsByStatus);


module.exports = router;
