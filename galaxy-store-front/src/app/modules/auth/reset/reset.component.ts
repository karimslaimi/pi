import {Component, HostListener, OnInit} from '@angular/core';
import {AbstractControl, FormBuilder, FormGroup, ValidationErrors, ValidatorFn, Validators} from "@angular/forms";
import {AuthService} from "../../../core/services/auth.service";
import {ActivatedRoute, ActivatedRouteSnapshot, Router} from "@angular/router";

@Component({
  selector: 'app-reset',
  templateUrl: './reset.component.html',
  styleUrls: ['./reset.component.scss']
})
export class ResetComponent implements OnInit{
  submitted = false;
  successMessage: string;
  errorMessage: string;
  resetForm: FormGroup;
  showPassword: boolean = false;
  token: string | null;

  constructor(private formBuilder: FormBuilder, private authService: AuthService, private route :ActivatedRoute, private router : Router) {
    this.resetForm = this.formBuilder.group({
      password: ['', [Validators.required, Validators.minLength(6)]],
      confirmPassword: ['', [Validators.required, Validators.minLength(6)]]
    }, {validator: passwordConfirmationValidator()});
    this.resetForm.valueChanges.subscribe({
      next: e => {
        this.submitted = false;
      }
    });
  }

  ngOnInit(){
    this.token = this.route.snapshot.paramMap.get('token');
    if(!this.token){
      this.router.navigate(["/auth/login"]);
    }
  }


  onSubmit() {
    this.submitted = true;
    if (this.resetForm.invalid) {
      return;
    }

    this.authService.resetPassword(this.token!, this.resetForm.get('password')?.value).subscribe({
      next:()=>{this.router.navigate(['/auth/login']);},
      error:(e)=>{alert(e.error.message);return;}
    });


  }

  get formControls() {
    return this.resetForm.controls;
  }

  displayPassword() {
    this.showPassword = !this.showPassword;
  }

}

export function passwordConfirmationValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const password = control.get('password')?.value;
    const confirmPassword = control.get('confirmPassword')?.value;

    if (password !== confirmPassword) {
      return {passwordMismatch: true};
    }

    return null;
  };
}
