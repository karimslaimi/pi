import { Component, OnInit, OnDestroy, Input } from '@angular/core';
import { UserService } from 'src/app/core/services/user.service';
import { FormGroup, FormControl } from '@angular/forms';
import { Subscription, Observable } from 'rxjs';
import { mimeType } from '../create-post/mime-type-validator';
import { RouterLink } from '@angular/router';
import { User } from 'src/app/core/models/user.model';

@Component({
  selector: 'app-user-details',
  templateUrl: './user-details.component.html',
  styleUrls: ['./user-details.component.scss']
})
export class UserDetailsComponent implements OnInit, OnDestroy {
  @Input() isProfile: boolean | any;
  user: any;
  userSubscription: Subscription | any;
  userProfile: User | any = null;
  userProfileSubscription: Subscription | any;
  form: FormGroup | any;
  constructor(private userService: UserService) { }

  ngOnInit() {

    // if in profil page or home
    this.userProfileSubscription = this.userService.getUserProfile().subscribe( (userProfile: User | any) => {
      if (userProfile) {
        this.userProfile = userProfile;
      }
    });
    
    this.userSubscription = this.userService.getUser().subscribe( (user: any) => {
      this.user = user;
    });

    this.form = new FormGroup({
      image: new FormControl(null, {asyncValidators: mimeType})
    });
  }


  changeImage(event: Event) {
    const file = (event.target as HTMLInputElement)?.files?.[0];
    this.form.patchValue({image: file});      
    this.userService.changeImage(this.form.value.image);
  }

  userHasImage(userImage:string,userProfileImage:string, isProfile:boolean) {
    if (!isProfile) {
      if (userImage) {
        return userImage;
      } else {
        return false;
      }
    }

    if (userProfileImage) {
      return userProfileImage;
    } else {
      return false;
    }
  }

  canChangeImage(userId:string, userProfileId:string, isProfile:boolean) {
    if (!isProfile) {
      return true;
    }

    if (isProfile) {
      if (userId === userProfileId) {
        return true;
      } else return false;
    }
    return false;
  }
  

  ngOnDestroy() {
    this.userSubscription.unsubscribe();
    if (this.userProfileSubscription) {
      this.userProfileSubscription.unsubscribe();
    }
  }
}
