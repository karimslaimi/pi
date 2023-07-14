let rooms = [];
let roomHistory = {};
const users = {};

module.exports = (socket, io) => {
    console.log('User connected');
        let user;
        
        socket.on('startCall', (data) => {
          socket.broadcast.emit('incomingCall', data);
        });
      
        socket.on('answerCall', (data) => {
          socket.broadcast.emit('callAnswered');
        });
      
        socket.on('cancelCall', (data) => {
          socket.broadcast.emit('callCancelled');
        });
        
        
        socket.on('joinRoom', (data) => {
          const { room, username } = data;
          socket.join(room);
          const user = {
            id: socket.id,
            username,
            room,
            image: data.image,
            peerID: data.peerID
          };
          users[socket.id] = user;
          if (!rooms.includes(room)) {
            rooms.push(room);
            roomHistory[room] = [];
            io.emit('roomList', rooms);
          }
          socket.emit('historyMessages', roomHistory[room]);
          updateUserList(room);
        });
      
        socket.on('leaveRoom', (room) => {
          socket.leave(room);
          const index = rooms.indexOf(room);
          if (index !== -1) {
            rooms.splice(index, 1);
            delete roomHistory[room];
            io.emit('roomList', rooms);
          }
          delete users[socket.id];
          updateUserList(room);
        });
      
        socket.on('sendMessage', (data) => {
          const { room, message } = data;
          const messageData = {
            user: data.user,
            message,
            date: new Date(),
            room: room
          };
          if (!roomHistory[room]) {
            roomHistory[room] = [];
          }
          roomHistory[room].push(messageData);
          if (roomHistory[room].length > 100) {
            roomHistory[room].shift();
          }
          io.to(room).emit('receiveMessage', messageData);
        });
      
        socket.on('getRooms', () => {
          socket.emit('roomList', rooms);
        });
      
        socket.on('getUsers', () => {
          const connectedUsers = Object.values(users).map((user) => ({
            username: user.username,
            image: user.image,
            peerID: user.peerID,
          }));
          socket.emit('userList', connectedUsers);
        });
      
        socket.on('disconnect', () => {
          delete users[socket.id];
          updateAllUserLists();
        });
      
        function updateUserList(room) {
          const userList = getUsersInRoom(room);
          io.to(room).emit('userList', userList);
        }
      
        function getUsersInRoom(room) {
          const usersInRoom = Object.values(users).filter(
            (user) => 1 == 1
          );
          return usersInRoom.map((user) => ({
            username: user.username,
            image: user.image,
            peerID: user.peerID,
          }));
        }
      
        function updateAllUserLists() {
          const connectedUsers = Object.values(users).map((user) => ({
            username: user.username,
            image: user.image,
            peerID: user.peerID,
          }));
          io.emit('userList', connectedUsers);
        }
}