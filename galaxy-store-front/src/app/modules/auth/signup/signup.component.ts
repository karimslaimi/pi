import { Component, OnInit } from '@angular/core';
import {
  FormGroup,
  FormControl,
  Validators,
  ValidationErrors,
} from '@angular/forms';
import { Router } from '@angular/router';
import { map } from 'rxjs/operators';
import { Observable } from 'rxjs';
import { AuthService } from 'src/app/core/services/auth.service';

@Component({
  selector: 'app-signup',
  templateUrl: './signup.component.html',
  styleUrls: ['./signup.component.scss'],
})
export class SignupComponent implements OnInit {
  form: FormGroup | any;
  isLoading: boolean = false;
  showPassword: boolean = false;

  constructor(private authService: AuthService, private router: Router) {}

  ngOnInit() {
    this.form = new FormGroup(
      {
        firstname: new FormControl(null, [
          Validators.required,
          Validators.minLength(4),
        ]),
        lastname: new FormControl(null, [
          Validators.required,
          Validators.minLength(4),
        ]),
        email: new FormControl(null, {
          validators: [Validators.required, Validators.email],
        }),
        password: new FormControl(null, [
          Validators.required,
          Validators.minLength(6),
        ]),
        confirmPassword: new FormControl(null, Validators.required),
      }
    );
  }

  submitSignup() {
    if (!this.form.invalid) {
      this.isLoading = true;
      const firstname = this.form.value.firstname;
      const lastname = this.form.value.lastname;
      const email = this.form.value.email;
      const password = this.form.value.password;
      const confirmPassword = this.form.value.confirmPassword;
      const signupData = {
        username: firstname+lastname,
        email: email,
        password: password,
        firstName: firstname,
        lastName: lastname,
        role : 'USER',
      };
      this.authService.signup(signupData).subscribe((result: any) => {
        if (result) this.router.navigate(['/home']);
      });
    }
  }

  matchPassword(formGroup: FormGroup) {
    /*let password = formGroup.get('password');
    let confirmPassword = formGroup.get('confirmPassword');
    return password.value !== confirmPassword.value
      ? { matchPassword: true }
      : null;*/
  }
  checkEmail(control: FormControl): Observable<ValidationErrors | null> {
    return this.authService.checkEmail(control.value).pipe(
      map((result: any) => {
        if (result.emailExist) {
          return { emailExist: true };
        } else {
          return null;
        }
      })
    );
  }

  displayPassword(){
    this.showPassword = !this.showPassword;
  }
}
