const mongoose = require('mongoose');

const claimSchema = new mongoose.Schema({
  description: {
    type: String,
    required: true
  },
  image: {
    type: String,
  },
  status: {
    type: String,
    enum: ['Pending', 'Approved', 'Rejected'],
    default: 'Pending'
  },
  claimType: {
    type: String,
    required: true
  },
  refId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  reply: {
    type: String,
    default: ''
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
});

const Claim = mongoose.model('Claim', claimSchema);

module.exports = Claim;
