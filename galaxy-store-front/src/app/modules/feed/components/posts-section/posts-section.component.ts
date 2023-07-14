import { Component, OnInit, Input, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { User } from 'src/app/core/models/user.model';
import { UserService } from 'src/app/core/services/user.service';

@Component({
  selector: 'app-posts-section',
  templateUrl: './posts-section.component.html',
  styleUrls: ['./posts-section.component.scss'],
})
export class PostsSectionComponent implements OnInit, OnDestroy {
  @Input() isProfile: boolean | any;
  @Input() userId: string | any;
  user: User | any;
  userSubscription: Subscription | any;

  constructor(private userService: UserService) {}

  ngOnInit() {
    this.userSubscription = this.userService
      .getUser()
      .subscribe((user: User) => {
        this.user = user;
      });
  }

  ngOnDestroy() {
    this.userSubscription.unsubscribe();
  }
}
