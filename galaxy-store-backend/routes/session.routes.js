const express = require('express');
const sessionController = require('../controllers/session.controller');
const router = express.Router();

router.post('/', sessionController.createSession);
router.get('/', sessionController.getAllSessions);
router.get('/:room', sessionController.getSessionByRoom);
router.put('/:sessionId', sessionController.updateSessionById);
router.delete('/:sessionId', sessionController.deleteSessionById);


module.exports = router;