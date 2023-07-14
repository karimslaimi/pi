import { NgModule } from '@angular/core';

import { CommonModule } from '@angular/common';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import {
  CreatePostComponent,
  EditPostComponent,
  PostsListComponent,
  PostsSectionComponent,
  UserDetailsComponent,
  ShareButtonsComponent
} from './components';
import { MainContentComponent, FeedDetailComponent } from './pages';
import { FeedRoutingModule } from './feed-routing.module';
import { TransformUsername } from 'src/app/pipes/username.pipe';
import { MatMenuModule } from '@angular/material/menu';
import { MatDialogModule } from '@angular/material/dialog';
import { ShareButtonsModule } from 'ngx-sharebuttons/buttons';
import { ShareIconsModule } from 'ngx-sharebuttons/icons';

@NgModule({
  declarations: [
    CreatePostComponent,
    EditPostComponent,
    PostsListComponent,
    PostsSectionComponent,
    UserDetailsComponent,
    MainContentComponent,
    FeedDetailComponent,
    ShareButtonsComponent,
    TransformUsername,
  ],
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    FeedRoutingModule,
    MatDialogModule,
    MatMenuModule,
    ShareButtonsModule.withConfig({
      debug: true,
    }),
    ShareIconsModule,
  ]
})
export class FeedModule {}
