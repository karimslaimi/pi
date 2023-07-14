const mongoose = require('mongoose');
const { Schema } = mongoose;
const ProductStatus = Object.freeze({
    PROCESSING: "PROCESSING",
    REJECTED: "REJECTED",
    VALIDATED: "VALIDATED",
  });
const schemaProduct = new Schema({

    name:{
        type :String,
        require:true
    },
    price:{
        type:Number,
        require:true
    },
    status: {
        type: String,
        enum: Object.values(ProductStatus),
        default: ProductStatus.PROCESSING,
      },
    matricule:{
        type:String ,
        require:true
    },
    dateFermeture:{
        type:String,
        require:true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
         ref: 'User',
         required: true
     },

     category: {
        type: mongoose.Schema.Types.ObjectId,
         ref: 'category',
         required: true
     },
},
)

const product = mongoose.model('product', schemaProduct);

module.exports = product;