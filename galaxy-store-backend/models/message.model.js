const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  user: {
    type: String,
    required: true,
  },
  date: {
    type: String,
    required: true,
  },
  room: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    required: true,
  },
  image: {
    type: String,
    required: true,
  },
  peerID: {
    type: String,
    required: true,
  },
});

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;
