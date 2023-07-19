import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import {ProfileComponent} from "./profile/profile.component";
import {UserListComponent} from "./user-list/user-list.component";

const routes: Routes = [
  { path :'updateProfile', component: ProfileComponent},
  { path :'list', component: UserListComponent}
];




@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class UsersRoutingModule { }
