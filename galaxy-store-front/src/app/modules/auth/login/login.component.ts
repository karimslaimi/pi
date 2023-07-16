import {Component, OnInit} from '@angular/core';
import {FormGroup, FormControl, Validators, AbstractControl} from '@angular/forms';
import {Router} from '@angular/router';
import {AuthService} from 'src/app/core/services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {

  form: FormGroup | any;
  backEndValidation: string | any;
  isLoading: boolean = false;
  usernameError: boolean = false;
  PasswordError: boolean = false;
  showPassword: boolean = false;

  constructor(private authService: AuthService, private router: Router) {
  }

  ngOnInit() {
    this.form = new FormGroup({
      username: new FormControl('', {validators: [Validators.required]}),
      password: new FormControl('', [Validators.required, Validators.minLength(6)])
    });

  }

  get f(): { [key: string]: AbstractControl } {
    return this.form.controls;
  }

  submitLogin() {
    if (!this.form.invalid) {
      this.isLoading = true;

      const username = this.form.value.username;
      const password = this.form.value.password;
      this.authService.login(username, password)
        .subscribe((result: boolean) => {
          if (result) this.router.navigate(['/chat/message']);
          this.isLoading = false;
          this.backEndValidation = "an error occured";
        }, (error) => {
          this.isLoading = false;
          console.log(error.error);
          this.backEndValidation = error.error["message"];
        });
    } else {
      this.validateUsername();
      this.validatePassword();
    }


  }


  validateUsername() {
    const control = this.form.username;
    if (control !== null && control.invalid) {
      this.usernameError = true;
      this.isLoading = true;
    }
  }

  validatePassword() {
    const control = this.form.password;
    if (control !== null && control.invalid) {
      this.PasswordError = true;
      this.isLoading = true;
    }
  }

  handleForgetPassword(){

  }

  displayPassword(){
    this.showPassword = !this.showPassword;
  }

}
