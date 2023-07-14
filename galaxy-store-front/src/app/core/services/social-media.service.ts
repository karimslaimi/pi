import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root',
})
export class SocialMediaService {
  private url: string = environment.API_URL + '/api/socialMedia';
  constructor(private http: HttpClient) {}

getSocialMedia(text: string, imagePath: string) {
    return this.http.post<any>(this.url, { text, imagePath });
  }
}
