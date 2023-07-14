import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute, Params } from '@angular/router';
import { Subscription } from 'rxjs';
import { Post } from 'src/app/core/models/post.model';
import { PostService } from 'src/app/core/services/post.service';
import { UserService } from 'src/app/core/services/user.service';


@Component({
  selector: 'app-feed-detail',
  templateUrl: './feed-detail.component.html',
  styleUrls: ['./feed-detail.component.scss']
})
export class FeedDetailComponent implements OnInit, OnDestroy {

  private routeSub: Subscription;
  post: Post | any;
  imagePreviewUrl: string | any;
  modalUp: boolean = false;

  constructor(private postService: PostService, private route: ActivatedRoute) { }

  ngOnInit() {
    this.routeSub = this.route.params.subscribe(params => {
      console.log(params) //log the entire params object
      console.log(params['id']) //log the value of id
      this.postService.getPostById(params['id']).subscribe((post: Post) => {
          this.post = post;
          console.log(post);
        });

    });
  }

  isVideo(file: string) {
    return file.endsWith('.mp4');
  }

  openModalImage(image: string) {
    this.imagePreviewUrl = image;
    this.modalUp = true;
  }

  closeModalImage() {
    this.modalUp = false;
  }


  ngOnDestroy() {
    this.routeSub.unsubscribe();
  }

}
