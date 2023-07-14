import { Component, OnInit, OnDestroy, Input } from '@angular/core';
import { PostService } from 'src/app/core/services/post.service';
import { EditPostComponent } from '../edit-post/edit-post.component';
import { Subscription } from 'rxjs';
import { UserService } from 'src/app/core/services/user.service';
import { FormControl, Validators } from '@angular/forms';
//import { MatDialog } from '@angular/material/dialog';
import { environment } from 'src/environments/environment';
import { io, Socket } from 'socket.io-client';
import { User } from 'src/app/core/models/user.model';
import { Post } from 'src/app/core/models/post.model';
import { MatDialog } from '@angular/material/dialog';

@Component({
  selector: 'app-posts-list',
  templateUrl: './posts-list.component.html',
  styleUrls: ['./posts-list.component.scss'],
})
export class PostsListComponent implements OnInit, OnDestroy {
  @Input() userId: string | any;
  posts: Post[] | any;
  postsSubscription: Subscription | any;
  user: any;
  userSubscription: Subscription | any;
  newComment: FormControl | any;
  editedComment: FormControl | any;
  editedCommentIndex: number = -1;
  isLoading: boolean = false;
  private socket!: Socket;
  idUser: string | null;
  imagePreviewUrl: string | any;
  modalUp: boolean = false;

  constructor(
    private postService: PostService,
    private dialog: MatDialog,
    private userService: UserService
  ) {}

  ngOnInit() {
    this.idUser = localStorage.getItem('userId');
    this.socket = io(environment.API_URL);
    this.isLoading = true;
    this.userSubscription = this.userService
      .getUser()
      .subscribe((user: User) => {
        this.user = user;
      });

    if (this.userId) {
      this.postsSubscription = this.postService
        .getAllPostsSubject()
        .subscribe((posts: Post[]) => {
          this.isLoading = false;
          this.posts = posts;
        });
      this.postService.userProfileId = this.userId;
    } else {
      this.postsSubscription = this.postService
        .getAllPostsSubject()
        .subscribe((posts: Post[]) => {
          this.isLoading = false;
          this.posts = posts;
        });
    }

    // websocket
    this.socket.on('posts', (data: any) => {
      console.log('Received socket event: ', data);
      this.postService.handleWebSocket(data);
    });

    this.newComment = new FormControl('', Validators.required);
  }

  deletePost(post: Post) {
    this.postService.deletePost(post.id);
  }

  editPost(post: Post) {
    this.dialog.open(EditPostComponent, { data: { post: post}});
  }

  likeClicked(post: Post) {
    if (this.isLiked(post)) {
      const likeIndex = post.likes.findIndex((like) => {
        return like.user === localStorage.getItem('userId');
      });
      this.deleteLike(likeIndex, post);
    } else {
      this.addLike(post);
    }
  }

  addLike(post: Post) {
    this.postService.addLike(post.id);
  }

  deleteLike(likeIndex: number, post: Post) {
    const likeId = post.likes[likeIndex]._id;
    this.postService.deleteLike(likeId, post.id);
  }

  isLiked(post: Post) {
    const isLiked = post.likes.findIndex((like) => {
      return like.user === localStorage.getItem('userId');
    });
    if (isLiked === -1) {
      return false;
    } else {
      return true;
    }
  }

  isVideo(file: string) {
    return file.endsWith('.mp4');
  }
  
  onEnterComment(post: Post) {
    const commentContent = this.newComment.value;
    this.postService.addComment(post.id, commentContent);
    this.newComment.reset();
  }

  deleteComment(comment: any, post: Post) {
    this.postService.deleteComment(comment._id, post.id);
  }

  enableEditComment(post: Post, comment: any) {
    this.editedCommentIndex = post.comments.findIndex((selectedComment) => {
      return selectedComment._id === comment._id;
    });
    this.editedComment = new FormControl(comment.content, Validators.required);
  }

  editComment(post: Post, comment: any) {
    const editCommentData = {
      postId: post.id,
      content: this.editedComment.value,
    };
    this.postService
      .updateComment(comment._id, editCommentData)
      .subscribe((result: boolean) => {
        if (result) {
          this.editedComment.reset();
          this.editedCommentIndex = -1;
        }
      });
  }

  closeModalImage() {
    this.modalUp = false;
  }

  openModalImage(image: string) {
    this.imagePreviewUrl = image;
    this.modalUp = true;
  }

  ngOnDestroy() {
    this.postsSubscription.unsubscribe();
    this.userSubscription.unsubscribe();
  }
}
