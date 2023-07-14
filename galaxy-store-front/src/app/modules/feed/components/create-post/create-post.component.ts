import { Component, OnInit, OnDestroy } from '@angular/core';
import { FormGroup, FormControl } from '@angular/forms';
import { PostService } from 'src/app/core/services/post.service';
import { mimeType } from './mime-type-validator';
import { Subscription } from 'rxjs';
// import { mimeType } from './mime-type-validator';

@Component({
  selector: 'app-create-post',
  templateUrl: './create-post.component.html',
  styleUrls: ['./create-post.component.scss']
})
export class CreatePostComponent implements OnInit, OnDestroy {
  imagePreviewUrl: string | any;
  form: FormGroup | any;
  isLoadingSub: Subscription | any;
  isLoading: boolean = false;

  constructor(private postService: PostService) { }

  ngOnInit() {
    this.form = new FormGroup({
      content: new FormControl(),
      image: new FormControl(null)
    })
    // spinner and clear form
    this.isLoadingSub = this.postService.isLoading.subscribe( result => {
      this.isLoading = result;
      this.form.reset();
    });

  }

  uploadImage(event: Event) {
    const target = (event.target as HTMLInputElement);
    let file = target?.files != null ? target.files[0] : null;
    this.form.patchValue({image: file});
    this.form.get('image').updateValueAndValidity();
    const fileReader = new FileReader();
    fileReader.onload = () => {
      this.imagePreviewUrl = fileReader.result as string;
    }
    if(file) {
      fileReader.readAsDataURL(file);
    }
  }

  savePost() {
    const content = this.form.value.content || undefined;
    const image = this.form.value.image || undefined;
    const newPostData = {content: content, image: image}; 
    this.postService.addPost(newPostData);
    this.imagePreviewUrl = '';
  }

  discardPost() {
    this.imagePreviewUrl = '';
    this.form.reset();
  }

  isVideo(file: string) {
    return file.includes('video/');
  }

  ngOnDestroy() {
    this.isLoadingSub.unsubscribe();
  }

}
