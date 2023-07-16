import {Component} from '@angular/core';
import {FormBuilder, FormGroup, Validators} from "@angular/forms";
import {AuthService} from "../../../core/services/auth.service";

@Component({
  selector: 'app-forget-password',
  templateUrl: './forget-password.component.html',
  styleUrls: ['./forget-password.component.scss']
})
export class ForgetPasswordComponent {

  forgotPasswordForm: FormGroup;
  submitted = false;
  successMessage: string;
  errorMessage: string;

  constructor(
    private formBuilder: FormBuilder,
    private authService: AuthService // Inject your authentication service
  ) {
    this.forgotPasswordForm = this.formBuilder.group({
      email: ['', [Validators.required, Validators.email]]
    });
    this.forgotPasswordForm.valueChanges.subscribe({
      next: e => {
        this.submitted = false;
      }
    });
  }

  get formControls() {
    return this.forgotPasswordForm.controls;
  }

  onSubmit() {
    this.submitted = true;

    if (this.forgotPasswordForm.invalid) {
      return;
    }

    const email = this.forgotPasswordForm.value.email;
    this.authService.forgotPassword(email).subscribe({
      next: x => {
        this.successMessage = 'An email with instructions to reset your password has been sent.';
        this.errorMessage = '';
        this.submitted = false;
      }
      ,
      error: error => {
        this.successMessage = '';
        this.errorMessage = error;
      }
    });
  }
}
