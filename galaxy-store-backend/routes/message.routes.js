const express = require('express');
const messageController  = require('../controllers/message.controller');
const router = express.Router();

router.post('/', messageController.createMessage);
router.get('/', messageController.getAllMessages);
router.get('/:messageId', messageController.getMessageById);
router.put('/:messageId', messageController.updateMessageById);
router.delete('/:messageId', messageController.deleteMessageById);


module.exports = router;