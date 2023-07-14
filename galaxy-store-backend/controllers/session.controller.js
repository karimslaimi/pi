const Session = require('../models/session.model.js');

// Create a new session
const createSession = async (req, res) => {
  try {
    const session = new Session();
    await session.save();

    res.status(201).json(session);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create a session' });
  }
};

// Get all sessions
const getAllSessions = async (req, res) => {
  try {
    const sessions = await Session.find().populate('messages');
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve sessions' });
  }
};

// Get a single session by ID
const getSessionById = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = await Session.findById(sessionId).populate('messages');

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    res.json(session);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve the session' });
  }
};

// Update a session by ID
const updateSessionById = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { /* update session properties */ } = req.body;

    const updatedSession = await Session.findByIdAndUpdate(
      sessionId,
      { /* update session properties */ },
      { new: true }
    );

    if (!updatedSession) {
      return res.status(404).json({ error: 'Session not found' });
    }

    res.json(updatedSession);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update the session' });
  }
};

// Delete a session by ID
const deleteSessionById = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const deletedSession = await Session.findByIdAndDelete(sessionId);

    if (!deletedSession) {
      return res.status(404).json({ error: 'Session not found' });
    }

    res.json({ message: 'Session deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete the session' });
  }
};

const getSessionByRoom = async (req, res) => {
    try {
      const { room } = req.params;
      const session = await Session.findOne({ room }).populate('messages');
  
      if (!session) {
        return res.status(200).json([]);
      }
  
      res.json(session);
    } catch (error) {
      res.status(500).json({ error: 'Failed to retrieve the session' });
    }
  };

module.exports = {
  createSession,
  getAllSessions,
  getSessionById,
  updateSessionById,
  deleteSessionById,
  getSessionByRoom
};
