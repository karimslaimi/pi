import { Component, OnInit, OnDestroy, Input } from '@angular/core';
import { FaIconLibrary } from '@fortawesome/angular-fontawesome';
import {
  animate,
  state,
  style,
  transition,
  trigger,
} from '@angular/animations';
import { SocialMediaService } from 'src/app/core/services/social-media.service';

@Component({
  selector: 'app-share-buttons',
  templateUrl: './share-buttons.component.html',
  styleUrls: ['./share-buttons.component.scss'],
  animations: [
    trigger('fadeInOut', [
      state('void', style({ opacity: 0 })),
      state('*', style({ opacity: 1 })),
      transition(':enter', animate('300ms ease-in')),
      transition(':leave', animate('300ms ease-out')),
    ]),
  ],
})
export class ShareButtonsComponent implements OnInit, OnDestroy {
  @Input() id: string;
  @Input() title: string;
  @Input() image: string;
  @Input() url: string;

  urlToShare: any = {
    facebook: '',
    twitter: '',
    linkedin: '',
    instagram: '',
    reddit: '',
  };
  content: string = '';
  isLoading: boolean = false;
  hideIcons: boolean = true;

  toggleIcons() {
    this.hideIcons = !this.hideIcons;
  }

  constructor(private socialMediaService: SocialMediaService) {}

  ngOnInit() {
    this.socialMediaService
      .getSocialMedia(this.title, this.image)
      .subscribe((res) => {
        this.urlToShare = res;
        this.isLoading = false;
      });
  }

  isVideo(file: string) {
    return file.endsWith('.mp4');
  }

  goToLink(url: string) {
    window.open(url, '_blank');
  }

  ngOnDestroy() {}
}
