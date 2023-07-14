const mongoose = require("mongoose");
const ModePaiement = Object.freeze({
  CARD: "card",
  BANKACCOUNT: "bank_account",
});
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    name:String,
    firstName:String,
    username: String,
    email: String,
    statusUser:String,
    statusCompte:String,
    password: String,
    resetPasswordToken:String,
    resetPasswordExpires:String,
    modePaiement: {
      type: String,
      enum: Object.values(ModePaiement),
    },
    rib:String,
    roles: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Role"
      }
    ]

  })
);

module.exports = User;
