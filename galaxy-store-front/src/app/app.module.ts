import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { BitakonModule } from './Bitakon/bitakon.module';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { SocketIoConfig, SocketIoModule } from 'ngx-socket-io';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';
import { AuthInterceptor, ErrorInterceptor } from './core/interceptor';
import { environment } from 'src/environments/environment';
import { FeedModule } from './modules/feed/feed.module';
import { ChatModule } from './modules/messages/messages.module';
import { NavigationComponent } from './shared/navigation/navigation.component';
import { ShareButtonModule } from 'ngx-sharebuttons/button';
import { ShareIconsModule } from 'ngx-sharebuttons/icons';
import {NgxDatatableModule} from "@swimlane/ngx-datatable";

const config: SocketIoConfig = { url: environment.API_URL, options: {} };

@NgModule({
  declarations: [AppComponent, NavigationComponent],
  imports: [
    NgxDatatableModule,
    BrowserModule,
    FormsModule,
    ReactiveFormsModule,
    AppRoutingModule,
    BitakonModule,
    FeedModule,
    ChatModule,
    BrowserAnimationsModule,
    RouterModule,
    HttpClientModule,
    SocketIoModule.forRoot(config),
    ShareButtonModule,
    ShareIconsModule
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: ErrorInterceptor, multi: true },
  ],
  bootstrap: [AppComponent]
})
export class AppModule {}
