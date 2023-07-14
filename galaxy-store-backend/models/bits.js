const mongoose = require('mongoose');
const product = require('./product');
const { Schema } = mongoose;
const BitsStatus = Object.freeze({
    CLOSED: 'closed',
    PROGRESS: 'in progress',
  });
const schemaBits = new Schema({

    bitsSharedDateTime: {
        type:String,
        required:true,
    },

     user: {
        type: mongoose.Schema.Types.ObjectId,
         ref: 'User',
         required: true
     },
    product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'product',
        required: true
    },

    bitsSharePrice: {
        type:Number,
        required:true,
        default:product.price
    },
    status: {
        type: String,
        enum: Object.values(BitsStatus),
        default: BitsStatus.PROGRESS,
      },
},
)

const bits = mongoose.model('bits', schemaBits);

module.exports = bits;