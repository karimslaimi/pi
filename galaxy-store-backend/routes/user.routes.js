const express = require('express');
const { authJwt } = require("../middleware");
const router = express.Router();
const UserController = require("../controllers/user.controller");
const { isUser, isAdmin } = require('../middleware/authJwt.js');

router.get('/all', UserController.getAllUsers, [authJwt.verifyToken, isAdmin]);
router.get('/allUsers', UserController.getAllUsersWithRoleUser, [authJwt.verifyToken, isAdmin]);
router.get('/allAdmins', UserController.getAllAdmins, [authJwt.verifyToken, isAdmin]);
router.get('/getUserProfile', UserController.getUserProfile, [authJwt.verifyToken]);
router.put('/update/:id', UserController.updateUser, [authJwt.verifyToken, isAdmin]);
router.put('/updateUserProfile', UserController.updateUserProfile, [authJwt.verifyToken]);
router.put('/confirm/:id', UserController.confirmUser, [authJwt.verifyToken, isAdmin]);
router.put('/block/:id', UserController.blockAccount, [authJwt.verifyToken, isAdmin]);
router.put('/unblock/:id', UserController.unblockAccount, [authJwt.verifyToken, isAdmin]);
router.delete('/delete/:id', UserController.deleteUser, [authJwt.verifyToken, isAdmin]);

module.exports = router;