import { CanActivate } from "@angular/router";
import { ActivatedRouteSnapshot, RouterStateSnapshot, Router } from "@angular/router";
import { Observable } from "rxjs";
import { Injectable } from "@angular/core";
import { AuthService } from "../core/services/auth.service";

@Injectable()

export class AuthGaurd implements CanActivate {

    constructor(private authService: AuthService, private router: Router) {}

    canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean | 
        Observable<boolean> | Promise<boolean> | any {

        const isAuth = this.authService.checkAuth();
            if (isAuth) {
                return true;
            } else {
                this.router.navigate(['/auth/login']);
            }
    }
   
}