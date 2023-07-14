const express = require('express');
const mongoose = require('mongoose');
const app = express();
const http = require('http');
const server = http.createServer(app);
const path = require('path');
const cors = require('cors');
const cookieSession = require("cookie-session");
const socket_io = require('./util/socketIo');
const handleSockets = require('./util/messages');

socket_io.init(server);

socket_io.getIO().on('connection', (socket) => {
    handleSockets(socket, socket_io.getIO());
});

const postRoutes = require('./routes/post.routes');
const likeRoutes = require('./routes/like.routes');
const commentRoutes = require('./routes/comment.routes');
const messageRoutes = require('./routes/message.routes');
const sessionRoutes = require('./routes/session.routes');
const bitsRoutes = require('./routes/bits.routes');
const commandRoutes = require('./routes/command.routes');
const productRoutes = require('./routes/product.routes');
const factureRoutes = require('./routes/facture.routes');
const categoryRoutes = require('./routes/category.routes');
const userRoutes = require('./routes/user.routes');
const socialMediaRoutes = require('./routes/socialMedia.routes');
const paymentRoutes = require('./routes/payment.routes')
const claimRoutes = require('./routes/claim.routes');
const PORT = process.env.PORT || 3000;

// connect to DB
mongoose
    .connect(process.env.MONGO_URL || `mongodb://127.0.0.1:27017/galaxy_store`)
    .then(() => {
        console.log("Database connected")
    })
    .catch((err) => {
        console.log("Database connection error... ", err)
    });


//only parses json 
app.use(express.json());
app.use(
    cookieSession({
        name: "projectPi-session",
        secret: "COOKIE_SECRET",
        httpOnly: true
    })
);
// make images folder static available in root
app.use('/images', express.static(path.join(__dirname, 'images')));

// Access-Control-Allow
app.use(cors())

// API ROUTES
app.use('/api/posts', postRoutes);
app.use('/api/comments', commentRoutes);
app.use('/api/likes', likeRoutes);
app.use('/api/session', sessionRoutes);
app.use('/api/message', messageRoutes);
app.get("/", (req, res) => {
    res.json({ message: "Welcome to  application." });
});
require("./routes/auth.routes")(app);
app.use('/api/bits', bitsRoutes);
app.use('/api/commands', commandRoutes);
app.use('/api/products', productRoutes);
require('./crons/bits.cron');
require('./crons/factures.cron');
app.use('/api/factures',factureRoutes)
app.use('/api/categorys',categoryRoutes)
app.use('/api/users', userRoutes);
app.use('/api/socialMedia', socialMediaRoutes);
app.use('/api/payment', paymentRoutes);
app.use('/api/claim', claimRoutes);

// UTILS
require('./util/messages');
// ERROR HANDLING MIDDLEWARE
app.use((error, req, res, next) => {
    const status = error.statusCode || 500;
    const message = error.message;
    const data = error.data || undefined;
    res.status(status).json({ message: message, data: data });
});

// listening
server.listen(PORT, () => console.log(`listening to port ${PORT}`));
//require('./util/socketIo').init(server);