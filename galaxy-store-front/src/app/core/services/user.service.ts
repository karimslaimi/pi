import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { User } from '../models/user.model';
import { map } from 'rxjs/operators';
import { Subject, Observable, from } from 'rxjs';
@Injectable({
  providedIn: 'root',
})
export class UserService {
  private url: string = environment.API_URL + '/api/users/profiles';
  private userSub = new Subject<User>();
  user: User | any;
  private userProfileSub = new Subject<User>();
  constructor(private http: HttpClient) {}

  initUser(id: string) {
    this.http
      .get<any>(environment.API_URL + '/api/users/getUserProfile')
      .pipe(
        map((response) => {
          return this.transformUserData(response.user);
        })
      )
      .subscribe((user: User) => {
        this.user = user;
        this.userSub.next(user);
      });
  }
  getUser(): Observable<any> {
    return this.userSub.asObservable();
  }

  getUserByID(): any {
    this.http
      .get<any>(this.url + `/${localStorage.getItem('userId')}`)
      .pipe(
        map((response) => {
          return this.transformUserData(response.user);
        })
      )
      .subscribe((user: User) => {
        this.user = user;
        this.userSub.next(user);
      });
  }

  getUserByIDs(id: string): any {
    this.http
      .get<any>(this.url + `/${id}`)
      .pipe(
        map((response) => {
          return this.transformUserData(response.user);
        })
      )
      .subscribe((user: User) => {
        this.user = user;
        this.userSub.next(user);
      });
  }

  initUserProfile(id: string) {
    this.http
      .get<{ user: any }>(this.url + `/${id}`)
      .pipe(
        map((response) => {
          return this.transformUserData(response.user);
        })
      )
      .subscribe((user: any) => {
        this.userProfileSub.next(user);
      });
  }
  getUserProfile(): Observable<any | string> {
    if (this.userProfileSub) {
      return this.userProfileSub.asObservable();
    } else {
      return from('null');
    }
  }

  changeImage(image: any) {
    const formData = new FormData();
    formData.append('image', image, image.name);
    return this.http
      .post<{ message: string; user: any }>(this.url + '/image', formData)
      .pipe(
        map((response) => {
          return this.transformUserData(response.user);
        })
      )
      .subscribe((user: User) => {
        this.userProfileSub.next(user);
        this.userSub.next(user);
      });
  }

  transformUserData(user: any): User {
    return {
      id: user?._id,
      email: user?.email,
      username: user?.username,
      imageUrl: user?.imageUrl,
    };
  }
}
