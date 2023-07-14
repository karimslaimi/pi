const express = require('express');
const postController = require('../controllers/post.controller');
const validObjectId = require('../middleware/validObjectId');
const isAuth = require('../middleware/isAuth');
const multer = require('../middleware/uploadImage');
const router = express.Router();


// likes
router.post('/', [isAuth] , postController.postLike);
router.delete('/:id', [isAuth, validObjectId] , postController.deleteLike);

module.exports = router;