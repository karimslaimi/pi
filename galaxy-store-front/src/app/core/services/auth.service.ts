import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { environment } from "src/environments/environment";
import { catchError, map } from "rxjs/operators";
import jwt_decode from 'jwt-decode';
import { UserService } from "./user.service";
import { Router } from "@angular/router";
import { BehaviorSubject, throwError } from "rxjs";

@Injectable({
  providedIn: 'root'
})

export class AuthService {
  private url: string = environment.API_URL + "/api/auth";
  private isLogged = new BehaviorSubject<boolean>(false);
   expireDate:Date = new Date();


  constructor(private http: HttpClient, private userService: UserService, private router: Router) {
    let token = localStorage.getItem("token");

    if (token){
          const jwtToken = JSON.parse(atob(token.split('.')[1]));
          this.expireDate = new Date(jwtToken.exp * 1000);
          if (this.expireDate < new Date()){
            this.logout();
          }
    }

  }


  login(username: string, password: string) {
    const loginData = { username: username, password: password };
    const endpoint = this.url + "/signin";
    return this.http.post<any>(endpoint, loginData)
      .pipe(
        map(response => {
          localStorage.setItem('token', response?.token);
          localStorage.setItem('userId', `${response?.id}`);
          localStorage.setItem('username', `${response?.username}`);
          localStorage.setItem("role", response?.roles);
          const jwtToken = JSON.parse(atob(response.token.split('.')[1]));
          this.expireDate = new Date(jwtToken.exp * 1000);
          this.isLogged.next(true);
          return true;
        })
      );
  }

  signup(signupData: any) {
    return this.http
      .post<{ message: string, token: string, user: any }>(this.url + "/signup", signupData)
      .pipe(
        map(response => {
          localStorage.setItem('token', response?.token);
          this.isLogged.next(true);
          return true;
        })
      );
  }

  forgotPassword(email: string) {
    return this.http.post<any>(this.url + '/forgot-password', { email }).pipe(
      map(response => {
        localStorage.setItem("token", response?.resetToken);
        return response;
      }),
      catchError(error => {
        console.log(error);
        return throwError(() => 'Failed to send the password reset email. Please try again later.');
      })
    );
  }

  resetPassword(resetToken: string, newPassword: string) {
    return this.http.post(this.url + '/reset-password', { resetToken, newPassword }).pipe(
      map(response => {
        return response;
      }),
      catchError(err => {
        console.error(err.error.message);
        return throwError(() => err);
      })
    );
  }

  checkEmail(email: string) {
    return this.http.get<{ emailExist: boolean }>(this.url + `/checkemail/${email}`);
  }

  logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    this.isLogged.next(false);
    this.router.navigate(['/auth/login']).then(r => console.log("redirected"));
    return true;
  }

  // return true if loggedIn or false to AuthGaurd
  checkAuth() {
    let token = this.getToken();
    if (!token) {
      return false;
    }

    if (this.expireDate < new Date()){
      return false;
    }

    let decodedToken = jwt_decode<any>(token);




    this.isLogged.next(true);
    let userId = decodedToken.id;
    return true;

  }


  isLoggedIn() {
    return this.isLogged.value;
  }


  /*private setToken(token: string) {
      localStorage.setItem('token', token);
  }*/

  getToken(): string | null {
    const token = localStorage.getItem('token');
    if (token) {
      return token;
    } else {
      return null;
    }
  }

  getRole(): string | null {
    const role = localStorage.getItem("role");
    return role ?? null;
  }


}
