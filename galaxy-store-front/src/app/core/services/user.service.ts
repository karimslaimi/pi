import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {environment} from 'src/environments/environment';
import {User} from '../models/user.model';
import {catchError, map} from 'rxjs/operators';
import {Subject, Observable, from, of, throwError} from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class UserService {
  private url: string = environment.API_URL + '/api/users';
  private userSub = new Subject<User>();
  user: User | any;
  private userProfileSub = new Subject<User>();


  constructor(private http: HttpClient) {
  }


  getUser(): Observable<any> {
    return this.userSub.asObservable();
  }

  getUserByID(): any {
    this.http
      .get<any>(this.url + `/getUserProfile`)
      .pipe(
        map((response) => {
          debugger;
          let res = this.transformUserData(response.user);
          debugger;
          return new Observable<any>(o => {
            o.next(res);
          });
        })
      );
  }

  getUserProfile(): Observable<any> {
    return this.http.get(this.url + '/getUserProfile')
      .pipe(
        map((resp: any) => {
          return this.transformUserData(resp);
        }),
        catchError((err: any) => {
          console.error(err);
          return of(err);
        })
      );
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


  updateUser(user: any) {
    return this.http
      .put<any>(this.url + "/updateUserProfile", user)
      .pipe(
        map(response => {
            return true;
          },
          catchError(error => {
            console.log(error);
            return throwError(() => 'Failed to update user');
          })
        )
      );
  }


  transformUserData(user: any): User {
    return {
      id: user?._id,
      email: user?.email,
      username: user?.username,
    };
  }


  getAllUsers(){
    return this.http.get<any[]>(this.url+"/all").pipe(
      map((resp)=>{
        return resp
      }),
      catchError(err => {
        console.log(err);
        return err;
      })
    )
  }

  deleteUser(id:any){
    return this.http.delete(this.url+'/delete/'+id);
  }


  confirmAccount(id:any){
    return this.http.put(this.url+'/confirm/'+id,{});
  }

  blockAccount(id:any){
    return this.http.put(this.url+'/block/'+id,{});
  }

  unblockAccount(id:any){
    return this.http.put(this.url+'/unblock/'+id,{});

  }
}
