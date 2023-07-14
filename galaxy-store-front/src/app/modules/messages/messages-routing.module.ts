import { NgModule } from "@angular/core";
import { Routes, RouterModule } from "@angular/router";

import { ChatComponent } from "./pages";

const routes: Routes = [
    { path: '', redirectTo: 'message', pathMatch: 'full'},
    { path: 'message', component: ChatComponent },

]
@NgModule({
    imports: [
        RouterModule.forChild(routes)
    ],
    exports: [RouterModule]
})
export class ChatRoutingModule {}