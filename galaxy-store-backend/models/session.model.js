const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  room: {
    type: String,
    required: true,
  },
  messages: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message',
  }],
  // Other session properties
});

const Session = mongoose.model('Session', sessionSchema);

module.exports = Session;
