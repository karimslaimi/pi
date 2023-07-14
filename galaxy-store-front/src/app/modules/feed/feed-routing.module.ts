import { NgModule } from "@angular/core";
import { Routes, RouterModule } from "@angular/router";

import { FeedDetailComponent, MainContentComponent } from "./pages";
import { ProfileUserResolver } from "src/app/core/utils/resolve-profile-user.service";

const routes: Routes = [
    { path: '', redirectTo: 'home', pathMatch: 'full'},
    { path: 'home', component: MainContentComponent },
    { path: 'post/:id', component: FeedDetailComponent },
    {
      path: 'profile/user/:id',
      component: MainContentComponent,
      resolve: { profileUser: ProfileUserResolver },
    },
]
@NgModule({
    imports: [
        RouterModule.forChild(routes)
    ],
    exports: [RouterModule]
})
export class FeedRoutingModule {}