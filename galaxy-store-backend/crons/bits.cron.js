const cron = require('node-cron');
const Bits = require('../models/bits');
const moment = require('moment-timezone');

cron.schedule('0 0 * * *', async () => {
    try {
        const bits = await Bits.find().populate('product');
        if(!bits){
            console.log("there is no bits");
        }else{
            for (const bit of bits) {
                const product = bit.product;
                const endProductTime = product.dateFermeture;
                if (endProductTime<moment().format('YYYY-MM-DD HH:mm:ss') || endProductTime===moment().format('YYYY-MM-DD HH:mm:ss')) {
                    bit.status = 'closed';
                    await bit.save();
                    console.log('Cron job executed successfully!');
                }
            }
        }
    } catch (error) {
        console.error('Error executing cron job:', error);
    }
});
