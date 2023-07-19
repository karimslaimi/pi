import {Component, OnInit} from '@angular/core';
import {AbstractControl, FormControl, FormGroup, ValidationErrors, ValidatorFn, Validators} from '@angular/forms';
import {UserService} from "../../../core/services/user.service";

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.scss']
})
export class ProfileComponent implements OnInit {

  form: FormGroup | any;
  user: any = null;
  isLoading = false;
  errorMsg ="";
  successMsg="";
  showPassword = false;

  constructor(private userService: UserService) {
  }

  ngOnInit() {
    this.initializeForm();
    this.userService.getUserProfile().subscribe({
      next: (x: any) => {
        this.user = x;
        this.initializeForm();
      },
      error: () => {
        throw new Error("error");
      }
    });
    this.form.valueChanges.subscribe({
      next: ()=> {
        this.isLoading = false;
        this.successMsg="";
        this.errorMsg="";
      }
    });
  }

  initializeForm() {

    this.form = new FormGroup({
      username: new FormControl(this.user?.username ?? '', [
        Validators.required,
        Validators.minLength(4),
      ]),
      email: new FormControl(this.user?.email ?? '', [
        Validators.required,
        Validators.email,
      ]),
      password: new FormControl('', [
        passwordValidator
      ]),
      confirmPassword: new FormControl(''),
    });
  }

  onSubmit() {
    if (!this.form.invalid) {
      this.isLoading = true;
      let updateProfileData: any = {
        username: this.form.value.username,
        email: this.form.value.email,
      }
      if (this.form.value.password) {
        updateProfileData = {
          username: this.form.value.username,
          email: this.form.value.email,
          password: this.form.value.password
        }
      }

      this.userService.updateUser(updateProfileData).subscribe({
        next:(response)=>{
          this.userService.getUserProfile().subscribe({
            next: (x: any) => {
              this.user = x;
              this.initializeForm();
            },
            error: () => {
              throw new Error("error");
            }
          });
          this.isLoading = false;
          this.initializeForm();
          this.successMsg ="profile updated successfully";
        },
        error:(error)=>{
          this.isLoading = false;
          this.errorMsg = "an error occured while updating the profile";
        }
      })
    }
  }



  displayPassword(){
    this.showPassword = !this.showPassword;
  }


}

export function passwordValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {

    const value = control.value;
    if (value && value.trim().length > 0 && value.trim().length < 6) {
      return {'passwordLength': true};
    }

    return null;
  }

}

