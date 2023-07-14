import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { UserService } from './user.service';

@Injectable({
  providedIn: 'root',
})
export class MessagesService {
  private url: string = environment.API_URL + '/api/message';
  public headers = { 'content-type': 'application/json' };

  constructor(private http: HttpClient, private userService: UserService) {}

  getMessages() {
    return this.http.get<any>(this.url);
  }

  getMessage(id: string) {
    return this.http.get<any>(this.url + `/${id}`);
  }

  createMessage(message: any) {
    return this.http.post<any>(this.url, message);
  }

  updateMessage(id: string, message: any) {
    return this.http.put<any>(this.url + `/${id}`, message, {
      headers: this.headers,
    });
  }

  deleteMessage(id: string) {
    return this.http.delete<any>(this.url + `/${id}`);
  }
}
