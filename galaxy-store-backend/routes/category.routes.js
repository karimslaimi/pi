const express = require('express');
const router = express.Router();
const CategoryController = require('../controllers/category.controller.js');
const { authJwt } = require("../middleware");
const { isUser, isAdmin } = require('../middleware/authJwt.js');

router.post('/save',CategoryController.createCategory,[authJwt.verifyToken,isAdmin]);
router.get('/all',CategoryController.getAllCategorys,[authJwt.verifyToken,isAdmin]);
router.get('/categoryIdAdmin/:categoryId',CategoryController.getCategoryById,[authJwt.verifyToken,isAdmin]);
router.delete('/delete/:categoryId',CategoryController.deleteCategory,[authJwt.verifyToken,isAdmin]);
router.put('/update/:categoryId',CategoryController.updateCategory,[authJwt.verifyToken,isAdmin]);

module.exports = router;