const cron = require('node-cron');
const Facture = require('../models/facture.model');
const moment = require('moment-timezone');
const Commande = require('../models/command')
cron.schedule('0 0 * * *', async () => {
    try {
        const factures = await Facture.find().populate('command');
        if(!factures){
            console.log("there is no factures");
        }else{
            for (const facture of factures) {
                const command = facture.command;
                const endFactureTime = facture.dateEcheance;
                if (endFactureTime<moment().format('YYYY-MM-DD HH:mm:ss') || endFactureTime===moment().format('YYYY-MM-DD HH:mm:ss')) {
                    facture.status = 'EXPIRED';
                    facture.isRejected=true;
                    await facture.save();
                    command.status='REJECTED';
                    await command.save();
                    console.log('Cron Facture job executed successfully!');
                }
            }
        }
    } catch (error) {
        console.error('Error executing cron job:', error);
    }
});
