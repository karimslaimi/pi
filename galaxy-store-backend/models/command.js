const mongoose = require('mongoose');
const { Schema } = mongoose;

const CommandStatus = Object.freeze({
    PROCESSING: "PROCESSING",
    FACTURED: "FACTURED",
    VALIDATED: "COMPLETED",
    REJECTED:"REJECTED"
  });

  const schemaCommande = new Schema(
    {
      matriculeCommande: {
        type: String,
        required: true,
      },
      montantCommande: {
          type: Number,
          required: true,
        },
      status: {
          type: String,
          enum: Object.values(CommandStatus),
          default: CommandStatus.PROCESSING,
        },
      bits:{
            type: mongoose.Schema.Types.ObjectId,
            ref: 'bits',
            required: true
        },
      administator: {
            type: mongoose.Schema.Types.ObjectId,
             ref: 'User',
             required: true
         },

      receptorOfCommand: {
          type: mongoose.Schema.Types.ObjectId,
           ref: 'User',
           required: true
       },

       proprietaryOfProduct: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
       }
      
    },
    { timestamps: true }
  );
  
const Command = mongoose.model('command', schemaCommande);
  
module.exports = Command;
  