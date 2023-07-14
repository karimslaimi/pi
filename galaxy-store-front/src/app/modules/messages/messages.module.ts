import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatDialogModule } from '@angular/material/dialog';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

import { ChatRoutingModule } from './messages-routing.module';
import { ChatComponent } from './pages';
import { CallService } from 'src/app/core/services/call.service';
import { SocketIoConfig, SocketIoModule } from 'ngx-socket-io';
import { environment } from 'src/environments/environment';
import { MatMenuModule} from '@angular/material/menu';
import { RoomUsername } from 'src/app/pipes/room.pipe';

const config: SocketIoConfig = { url: environment.API_URL, options: {} };

@NgModule({
  declarations: [ChatComponent, RoomUsername],
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    ChatRoutingModule,
    MatDialogModule,
    SocketIoModule.forRoot(config),
    MatMenuModule
  ],
  providers: [CallService],
})
export class ChatModule {}
