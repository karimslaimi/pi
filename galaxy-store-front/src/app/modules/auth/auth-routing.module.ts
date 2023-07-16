import { NgModule } from "@angular/core";
import { Routes, RouterModule } from "@angular/router";
import { LoginComponent } from "./login/login.component";
import { SignupComponent } from "./signup/signup.component";
import {ForgetPasswordComponent} from "./forget-password/forget-password.component";
import {ResetComponent} from "./reset/reset.component";

const routes: Routes = [
    { path: '', redirectTo: 'login', pathMatch: 'full'},
    { path: 'login' , component: LoginComponent},
    { path: 'register', component: SignupComponent},
    { path: 'forget-password', component: ForgetPasswordComponent},
]
@NgModule({
    imports: [
        RouterModule.forChild(routes)
    ],
    exports: [RouterModule]
})
export class AuthRoutingModule {}
