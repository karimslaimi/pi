import { Injectable } from '@angular/core';
import Peer, { MediaConnection, PeerJSOption } from 'peerjs';
import { BehaviorSubject, Observable, Subject } from 'rxjs';
import { Socket, io } from 'socket.io-client';
import { environment } from 'src/environments/environment';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class CallService {
  private peer: Peer;
  private mediaCall: MediaConnection;

  private localStreamBs: BehaviorSubject<MediaStream | any> =
    new BehaviorSubject(null);
  public localStream$ = this.localStreamBs.asObservable();
  private remoteStreamBs: BehaviorSubject<MediaStream | any> =
    new BehaviorSubject(null);
  public remoteStream$ = this.remoteStreamBs.asObservable();

  private isCallStartedBs = new Subject<boolean>();
  public isCallStarted$ = this.isCallStartedBs.asObservable();

  private socket: Socket;

  constructor() {
    this.socket = io(environment.API_URL);
  }
  public initPeer(): any {
    if (!this.peer || this.peer.disconnected) {
      const peerJsOptions: PeerJSOption = {
        debug: 3,
        config: {
          iceServers: [
            {
              urls: environment.ICE_SERVERS,
            },
          ],
        },
      };
      try {
        let id = uuidv4();
        this.peer = new Peer(id, peerJsOptions);
        return id;
      } catch (error) {
        console.error(error);
      }
    }
  }

  public async establishMediaCall(remotePeerId: string) {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true,
      });

      const connection = this.peer.connect(remotePeerId);
      connection.on('error', (err) => {
        console.error(err);
        //this.snackBar.open(`${err}`, 'Close');
      });

      this.mediaCall = this.peer.call(remotePeerId, stream);
      if (!this.mediaCall) {
        let errorMessage = 'Unable to connect to remote peer';
        //this.snackBar.open(errorMessage, 'Close');
        throw new Error(errorMessage);
      }
      this.localStreamBs.next(stream);
      this.isCallStartedBs.next(true);

      this.mediaCall.on('stream', (remoteStream) => {
        this.remoteStreamBs.next(remoteStream);
      });
      this.mediaCall.on('error', (err) => {
        //this.snackBar.open(`${err}`, 'Close');
        console.error(err);
        this.isCallStartedBs.next(false);
      });
      this.mediaCall.on('close', () => this.onCallClose());
    } catch (ex) {
      console.error(ex);
      //this.snackBar.open(ex, 'Close');
      this.isCallStartedBs.next(false);
    }
  }

  public async enableCallAnswer() {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true,
      });
      this.localStreamBs.next(stream);
      this.peer.on('call', async (call) => {
        this.mediaCall = call;
        this.isCallStartedBs.next(true);

        this.mediaCall.answer(stream);
        this.mediaCall.on('stream', (remoteStream) => {
          this.remoteStreamBs.next(remoteStream);
        });
        this.mediaCall.on('error', (err) => {
          //this.snackBar.open(`${err}`, 'Close');
          this.isCallStartedBs.next(false);
          console.error(err);
        });
        this.mediaCall.on('close', () => this.onCallClose());
      });
    } catch (ex) {
      console.error(ex);
      //this.snackBar.open(ex, 'Close');
      this.isCallStartedBs.next(false);
    }
  }

  private onCallClose() {
    this.remoteStreamBs?.value.getTracks().forEach((track: any) => {
      track.stop();
    });
    this.localStreamBs?.value.getTracks().forEach((track: any) => {
      track.stop();
    });
    //this.snackBar.open('Call Ended', 'Close');
  }

  public closeMediaCall() {
    this.mediaCall?.close();
    if (!this.mediaCall) {
      this.onCallClose();
    }
    this.isCallStartedBs.next(false);
  }

  public destroyPeer() {
    this.mediaCall?.close();
    this.peer?.disconnect();
    this.peer?.destroy();
  }

  call(data: any) {
    this.socket.emit('call', data);
  }

  answer() {
    this.socket.emit('answer');
  }

  cancel() {
    this.socket.emit('cancel');
  }

  onIncomingCall(): Observable<any> {
    return new Observable((observer) => {
      this.socket.on('incomingCall', (data) => {
        observer.next(data);
      });
    });
  }

  onCallAnswered(): Observable<any> {
    return new Observable((observer) => {
      this.socket.on('callAnswered', () => {
        observer.next();
      });
    });
  }

  onCallCancelled(): Observable<any> {
    return new Observable((observer) => {
      this.socket.on('callCancelled', () => {
        observer.next();
      });
    });
  }
}
