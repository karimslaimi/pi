const mongoose = require('mongoose');
const { Schema } = mongoose;

const schemaTransaction = new Schema(
    {
      ribEmetteur: {
        type: String,
        required: true,
      },
      montantTransaction: {
          type: Number,
          required: true,
        },
      ribRecepteur: {
        type: String,
        required: true,
       },
      isDone:{
        type:Boolean,
        default :false
      },
      datePaiement:{
        type:String,
        required:true
       },
    },
    { timestamps: true }
  );
  
const Transaction = mongoose.model('Transaction', schemaTransaction);
  
module.exports = Transaction;
  