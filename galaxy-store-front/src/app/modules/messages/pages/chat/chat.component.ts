import { Component, ElementRef, OnInit, ViewChild } from '@angular/core';
import { Observable, filter, of } from 'rxjs';
import { Socket } from 'ngx-socket-io';
import { CallService } from 'src/app/core/services/call.service';
import { MessagesService } from 'src/app/core/services/messages.service';
import { SessionsService } from 'src/app/core/services/sessions.service';

@Component({
  selector: 'chat-component',
  templateUrl: './chat.component.html',
  styleUrls: ['./chat.component.scss'],
})
export class ChatComponent implements OnInit {
  rooms: any[] = [];
  userList: any[] = [];
  dataCalled: any = {
    caller: '',
    called: '',
    room: '',
  };
  messages: any[] = [];
  currentRoom: string = 'General';
  messageText: string = '';
  currentUser: any = localStorage.getItem('username') || 'No identified';
  userRemote: any = {};
  openUserList: boolean = false;
  calling: boolean = false;
  inCall: boolean = false;
  noCall: boolean = true;
  iIamCalling: boolean = false;
  activeTab: string = 'rooms';
  public isCallStarted$: Observable<boolean>;
  private peerId: string;
  peerRemoteId: string;
  @ViewChild('localVideo') localVideo: ElementRef<HTMLVideoElement>;
  @ViewChild('remoteVideo') remoteVideo: ElementRef<HTMLVideoElement>;

  constructor(
    private socket: Socket,
    private callService: CallService,
    private messagesService: MessagesService,
    private sessionsService: SessionsService
  ) {
    this.isCallStarted$ = this.callService.isCallStarted$;
    this.peerId = this.callService.initPeer();
  }

  ngOnInit() {
    this.callService.localStream$
      .pipe(filter((res) => !!res))
      .subscribe(
        (stream) => (this.localVideo.nativeElement.srcObject = stream)
      );
    this.callService.remoteStream$
      .pipe(filter((res) => !!res))
      .subscribe(
        (stream) => (this.remoteVideo.nativeElement.srcObject = stream)
      );
    this.joinRoomByName('General');
    //this.callUser();
    this.socket.on('receiveMessage', (message: any) => {
      if (message.room == this.currentRoom) {
        if (this.messages && this.messages.length > 0) {
          this.messages.push(message);
        } else {
          this.messages = [message];
        }
      }
    });
    this.socket.emit('getRooms');

    this.socket.on('roomList', (rooms: string[]) => {
      this.rooms = rooms.filter((room) => !room.startsWith('S'));
    });

    this.sessionsService.getSessionByRoom(this.currentRoom).subscribe(
      (res) => {
        if (res) {
          this.messages = res.messages;
        }
      },
      (err) => {
        console.error('Error: ', err);
      }
    );
    this.socket.on('historyMessages', (history: any[]) => {
      //this.messages = history;
      this.sessionsService.getSessionByRoom(this.currentRoom).subscribe(
        (res) => {
          if (res) {
            this.messages = res.messages;
          }
        },
        (err) => {
          console.error('Error: ', err);
        }
      );
    });

    this.socket.on('incomingCall', (data: any) => {
      if (data.called == this.currentUser) {
        //this.showModal(false);
        //this.answerCall();
        this.dataCalled = data;
        this.inCall = true;
      }
    });

    this.socket.on('callAnswered', (data: any) => {
      this.inCall = false;
      this.noCall = false;
      this.userRemote.username = 'User';
      this.showModal(true);
    });

    this.socket.on('callCancelled', (data: any) => {
      this.noCall = true;
      this.calling = false;
      this.callService.closeMediaCall();
      this.callService.destroyPeer();
      this.closeMediaStreams();
    });

    this.listenForUserList();
    this.getUsers();
  }

  joinRoom() {
    this.socket.emit('joinRoom', {
      room: this.currentRoom,
      username: this.currentUser,
      image: 'https://www.w3schools.com/howto/img_avatar.png',
      peerID: this.peerId,
    });

    this.sessionsService.getSessionByRoom(this.currentRoom).subscribe(
      (res) => {
        if (res) {
          this.messages = res.messages;
        }
      },
      (err) => {
        console.error('Error: ', err);
      }
    );
  }

  joinRoomByName(name: string) {
    this.socket.emit('joinRoom', {
      room: name,
      username: this.currentUser,
      image: 'https://www.w3schools.com/howto/img_avatar.png',
      peerID: this.peerId,
    });
  }

  swapRoom(room: string) {
    //this.leaveRoom();
    this.currentRoom = room;
    this.joinRoom();
  }

  leaveRoom() {
    this.socket.emit('leaveRoom', this.currentRoom);
    this.messages = [];
  }

  sendMessage(): void {
    const messageData = {
      user: this.currentUser,
      message: this.messageText,
      date: new Date(),
      room: this.currentRoom,
      image: 'https://www.w3schools.com/howto/img_avatar.png',
      peerID: this.peerId,
    };

    this.messagesService.createMessage(messageData).subscribe(
      (res) => {
        console.log('Message created: ');
      },
      (err) => {
        console.error('Error: ', err);
      }
    );

    this.socket.emit('sendMessage', messageData);
    this.messageText = '';
  }

  listenForUserList() {
    this.socket.on('userList', (userList: string[]) => {
      this.userList = userList.filter((item) => item !== this.currentUser);
    });

    this.socket.on('connect', () => {
      this.getUsers();
    });

    this.socket.on('disconnect', () => {
      this.userList = [];
    });
  }

  getUsers() {
    this.socket.emit('getUsers');
  }

  connectUser(user: any) {
    this.userRemote = user;
    this.peerRemoteId = user.peerID;
    const result = user.username.localeCompare(this.currentUser);

    if (result < 0) {
      this.swapRoom(`S-${user.username}-${this.currentUser}`);
    } else {
      this.swapRoom(`S-${this.currentUser}-${user.username}`);
    }
  }

  openUserListB(session: string) {
    this.activeTab = session;
    this.openUserList = !this.openUserList;
  }

  public showModal(joinCall: boolean): void {
    if (joinCall) {
      of(this.callService.establishMediaCall(this.peerRemoteId));
    } else {
      of(this.callService.enableCallAnswer());
    }
  }

  public endCall() {
    this.callService.closeMediaCall();
  }

  ngOnDestroy(): void {
    this.callService.destroyPeer();
  }

  callUser() {
    this.inCall = true;
    this.iIamCalling = true;
    this.calling = true;
    this.showModal(true);
    const data = {
      caller: this.currentUser,
      called: this.userRemote.username,
      peerID: this.peerId,
    };
    this.socket.emit('startCall', data);
  }

  answerCall() {
    this.inCall = false;
    this.noCall = false;
    this.calling = true;
    const data = {
      caller: this.currentUser,
      called: this.userRemote.username,
      peerID: this.peerId,
    };
    this.socket.emit('answerCall', data);
    this.showModal(false);
  }

  cancelCall() {
    this.noCall = true;
    this.calling = false;
    this.inCall = false;
    this.callService.closeMediaCall();
    this.callService.destroyPeer();
    this.closeMediaStreams();
    const data = {
      caller: this.currentUser,
      called: this.userRemote.username,
      peerID: this.peerId,
    };
    this.socket.emit('cancelCall', data);
  }

  closeMediaStreams(): void {
    const localVideoElement: HTMLVideoElement = this.localVideo.nativeElement;
    const remoteVideoElement: HTMLVideoElement = this.remoteVideo.nativeElement;

    // Stop the media streams
    const localStream: MediaStream = localVideoElement.srcObject as MediaStream;
    const remoteStream: MediaStream =
      remoteVideoElement.srcObject as MediaStream;

    if (localStream) {
      const tracks = localStream.getTracks();
      tracks.forEach((track) => track.stop());
    }

    if (remoteStream) {
      const tracks = remoteStream.getTracks();
      tracks.forEach((track) => track.stop());
    }

    localVideoElement.srcObject = null;
    remoteVideoElement.srcObject = null;
  }
}
