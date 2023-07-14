const mongoose = require('mongoose');
const { Schema } = mongoose;

const schemaCategory = new Schema({

    name:{
        type :String,
        require:true
    }
},
)

const Category = mongoose.model('category', schemaCategory);

module.exports = Category;