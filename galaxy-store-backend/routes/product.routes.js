const express = require('express');
const router = express.Router();
const ProductController = require('../controllers/product.controller.js');
const { authJwt } = require("../middleware");
const { isUser, isAdmin } = require('../middleware/authJwt.js');

router.post('/save',ProductController.createProduct,[authJwt.verifyToken,isUser]);
router.put('/update/:productId',ProductController.updateProduct,[authJwt.verifyToken,isUser]);
router.delete('/delete/:productId',ProductController.deleteProduct,[authJwt.verifyToken,isUser]);
router.get('/all',ProductController.getAllProducts,[authJwt.verifyToken,isAdmin]);
router.get('/valitedByCategory/:categoryId',ProductController.sortValitadedProductsByCategory,[authJwt.verifyToken,isAdmin]);
router.get('/allClosed',ProductController.getClosedProducts,[authJwt.verifyToken,isAdmin]);
router.get('/allByUser',ProductController.getAllProductsByUserConnected,[authJwt.verifyToken,isUser]);
router.put('/validate/:productId',ProductController.validateProduct,[authJwt.verifyToken,isAdmin]);
router.put('/reject/:productId',ProductController.rejectProduct,[authJwt.verifyToken,isAdmin]);
router.get('/allValidated',ProductController.getValidateProducts,[authJwt.verifyToken,isAdmin]);
router.get('/allRejected',ProductController.getRejectedProducts,[authJwt.verifyToken,isAdmin]);
router.get('/allInProgress',ProductController.getProcessingProducts,[authJwt.verifyToken,isAdmin]);
router.get('/product/:productId',ProductController.getProductById,[authJwt.verifyToken,isAdmin]);
router.get('/qr/:productId',ProductController.generateQRCode);
router.get('/allValidatedAndClosed',ProductController.getClosedAndValidatedProducts,[authJwt.verifyToken,isAdmin]);
router.get('/allValidatedAndAvailable',ProductController.getAvailableAndValidatedProducts,[authJwt.verifyToken,isUser]);

module.exports = router;