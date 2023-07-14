import { Injectable } from '@angular/core';
import {
  Resolve,
  RouterStateSnapshot,
  ActivatedRouteSnapshot
} from '@angular/router';
import { Observable, from } from 'rxjs';
import { User } from '../models/user.model';
import { UserService } from '../services/user.service';

 
@Injectable({
  providedIn: 'root',
})
export class ProfileUserResolver implements Resolve<User> {
  constructor(private userService:UserService) {}
 
  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<User> | 
  Observable<null> | any {
    
    if (route.params['id']) {
        this.userService.initUserProfile(route.params['id']);
    } else {
        return from("Error");
    }
    
  }
}