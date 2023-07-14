const Message = require('../models/message.model');
const Session = require('../models/session.model');

// Create a new message
const createMessage = async (req, res) => {
  try {
    const { user, date, room, message, image, peerID } = req.body;

    // Find or create the session based on the room name
    let session = await Session.findOne({ room });
    if (!session) {
      session = new Session({ room });
      await session.save();
    }

    // Create the new message
    const newMessage = new Message({ user, date, room, message, image, peerID });
    await newMessage.save();

    // Add the new message to the session's array of messages
    session.messages.push(newMessage._id);
    await session.save();

    res.status(201).json(newMessage);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create a message', error });
  }
};

// Get all messages
const getAllMessages = async (req, res) => {
  try {
    const messages = await Message.find();
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve messages' });
  }
};

// Get a single message by ID
const getMessageById = async (req, res) => {
  try {
    const { messageId } = req.params;
    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    res.json(message);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve the message' });
  }
};

// Update a message by ID
const updateMessageById = async (req, res) => {
  try {
    const { messageId } = req.params;
    const { user, date, room, image, peerID } = req.body;

    const updatedMessage = await Message.findByIdAndUpdate(
      messageId,
      { user, date, room, image, peerID },
      { new: true }
    );

    if (!updatedMessage) {
      return res.status(404).json({ error: 'Message not found' });
    }

    res.json(updatedMessage);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update the message' });
  }
};

// Delete a message by ID
const deleteMessageById = async (req, res) => {
  try {
    const { messageId } = req.params;

    // Remove the message from the associated session
    const session = await Session.findOneAndUpdate(
      { messages: messageId },
      { $pull: { messages: messageId } },
      { new: true }
    );

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    const deletedMessage = await Message.findByIdAndDelete(messageId);

    if (!deletedMessage) {
      return res.status(404).json({ error: 'Message not found' });
    }

    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete the message' });
  }
};

module.exports = {
  createMessage,
  getAllMessages,
  getMessageById,
  updateMessageById,
  deleteMessageById,
};
