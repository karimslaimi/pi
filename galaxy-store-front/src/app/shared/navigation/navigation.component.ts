import { Component } from '@angular/core';
import {AuthService} from "../../core/services/auth.service";
import {Router} from "@angular/router";

@Component({
  selector: 'app-navigation',
  templateUrl: './navigation.component.html',
  styleUrls: ['./navigation.component.scss']
})
export class NavigationComponent {

  constructor(public authService: AuthService, private router: Router) {
  }

  handleLogClickt() {

    if (this.authService.isLoggedIn()){
      this.authService.logout();
    }else{
      this.router.navigate(["/auth/login"]);
    }
  }
}
