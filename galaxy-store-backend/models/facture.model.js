const mongoose = require('mongoose');
const { Schema } = mongoose;
const FactureStatus = Object.freeze({
   PROCESSING: "PROCESSING",
   PAYED: "PAYED",
   EXPIRED: "EXPIRED",
 });
const schemaFacture = new Schema({

    matriculeFacture: {
        type:String,
        required:true,
    },

     command: {
        type: mongoose.Schema.Types.ObjectId,
         ref: 'command',
         required: true
     },

     isGenerated: {
        type:Boolean,
        required:true,
        default:false
     },

     isPayed: {
      type:Boolean,
      required:true,
      default:false
   },
    isRejected: {
      type:Boolean,
      required:true,
      default:false
    },

     document:{
        type:String,
        required:true
     },
     dateEcheance:{
      type:String,
      required:true
     },
     status: {
      type: String,
      enum: Object.values(FactureStatus),
    },
},
{ timestamps: true }
)

const factures = mongoose.model('facture', schemaFacture);

module.exports = factures;