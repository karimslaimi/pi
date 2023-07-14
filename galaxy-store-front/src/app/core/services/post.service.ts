import { Injectable, EventEmitter } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { map } from 'rxjs/operators';
import { Post } from '../models/post.model';
import { Subject, Observable } from 'rxjs';
import { UserService } from './user.service';


interface httpOptions {
  headers: HttpHeaders,
  body: any
}

@Injectable({
  providedIn: 'root'
})


export class PostService {
  private url: string = environment.API_URL + "/api/posts";
  private urlLike: string = environment.API_URL + "/api/likes";
  private posts: Post[] | any;
  private postsSubject = new Subject<Post[]>();
  isLoading = new EventEmitter<boolean>();
  isEditLoading = new EventEmitter<boolean>();
  httpOptions: httpOptions = {
    headers: new HttpHeaders({
      'Content-Type': 'application/json'
    }),
    body: null
  };
  userProfileId: any;

  constructor( private http: HttpClient, private userService: UserService) {}
  

  getAllPosts() {
    this.http.get<{posts: any[]}>(this.url)
    .pipe(
      map(response => {
        return response.posts.map( post => {
          return this.transformPostData(post);
        })
      })
    ).subscribe( (posts: Post[]) => {
      this.posts = posts;
      this.postsSubject.next([...this.posts]);
    });
  }
  getAllPostsSubject(): Observable<Post[]>{
    return this.postsSubject.asObservable();
  }

  getPostById(id: string) {
    return this.http.get<{post: any}>(this.url + `/${id}`)
    .pipe(
      map(response => {
        return this.transformPostData(response.post);
      })
    );
  }

  getUSerPosts(userId:string) {
    this.http.get<{posts: any[]}>(environment.API_URL + `/api/users/${userId}/posts`)
    .pipe(
      map(response => {
        return response.posts.map( post => {
          return  this.transformPostData(post);
        })
      })
    ).subscribe( (posts: Post[]) => {
      this.posts = posts;
      this.postsSubject.next([...this.posts]);
    });
  }

  addPost(postData: any) {
    this.isLoading.emit(true);
    const formData = new FormData();
    if (postData.content) formData.append("content", postData.content); 
    if (postData.image) {
      formData.append("image",postData.image , postData.image.name);
    }

    this.http.post<{message: string, post: any}>( this.url , formData)
    .pipe(
      map(response => {
        return this.transformPostData(response.post)
      })
    )
    .subscribe(createdPost => {
      this.posts.unshift(createdPost);
      this.postsSubject.next([...this.posts]);
      this.isLoading.emit(false);
    });
  }

  updatePost(id: any,postData: any) {
    this.isEditLoading.emit(true);
    const formData = new FormData();
    if (postData.content) {
      formData.append("content", postData.content);
    }
    if (postData.image) {
      formData.append("image",postData.image,postData.image.name);
    }
    
     this.http.put<{message: string, post: any}>( this.url + "/" + id , formData)
      .pipe(
        map( response => {
          return this.transformPostData(response.post);
        })
      ).subscribe((updatedPost: Post) => {
        let index = this.posts.findIndex( (post: Post) => {
          return post.id === updatedPost.id;
        });

        this.posts[index] = updatedPost;
        this.postsSubject.next([...this.posts]);
        this.isEditLoading.emit(false);
      });
  }




  deletePost(id: string) {
    this.http.delete<{message: string, post: any}>(this.url + `/${id}`)
    .pipe(
      map(response => {
        return this.transformPostData(response.post);
      })
    ).subscribe( (deletedPost: Post) => {
      let index = this.posts.findIndex( (post: Post, index: any) => {
        return post.id === deletedPost.id;
      });
      this.posts.splice(index,1);
      this.postsSubject.next([...this.posts]);
    });
  }


  addLike(postId: any) {
    this.http.post<{message: string, post: any}>( this.urlLike, {postId})
    .pipe(
      map( response => {
        return this.transformPostData(response.post);
      })
    ).subscribe( newPost => {
        const oldPostIndex = this.posts.findIndex((post: any) => {
          return post.id === newPost.id;
        });

        this.posts[oldPostIndex].likes = newPost.likes;
        this.postsSubject.next([...this.posts]);

    });
  }

  deleteLike(likedId: string, postId: string) {
    this.httpOptions.body = {postId, userId: localStorage.getItem('userId')};
    this.http.delete<{message: string, post:any}>(this.url+ `/likes/${likedId}`, this.httpOptions)
    .pipe(
      map( response => {
        return this.transformPostData(response.post);
      })
    ).subscribe((newPost: Post) => {
      const oldPostIndex = this.posts.findIndex((post: any) => {
        return post.id === newPost.id;
      });

      this.posts[oldPostIndex].likes = newPost.likes;
      this.postsSubject.next([...this.posts]);
    });
  }

  addComment(postId: any, content: any) {
    const requestBody = { postId: postId, content: content};
    this.http.post<{message: string, post:any}>(environment.API_URL + `/api/comments`, requestBody)
      .pipe(
        map( response => {
          return this.transformPostData(response.post);
        })
      ).subscribe((newPost: Post) => {
        const oldPostIndex = this.posts.findIndex((post: any) => {
          return post.id === newPost.id;
        });

        this.posts[oldPostIndex].comments = newPost.comments
        this.postsSubject.next([...this.posts]);
      })
  }


  deleteComment(commentId: any, postId: any) {
    this.httpOptions.body = {postId, userId: localStorage.getItem('userId')};
    this.http.delete<{message:string, post: any}>( environment.API_URL + `/api/comments/${commentId}`,
    this.httpOptions)
    .pipe(
      map( response => {
        return this.transformPostData(response.post);
      })
    ).subscribe((newPost: Post) => {
      const oldPostIndex = this.posts.findIndex( (post: any) => {
        return post.id === newPost.id;
      });

      this.posts[oldPostIndex].comments = newPost.comments
      this.postsSubject.next([...this.posts]);
    })
  }

  updateComment(commentId: any, editCommentData: any) {
    return this.http.put<{message: string, post:any}>(environment.API_URL+ `/api/comments/${commentId}`, editCommentData)
        .pipe(
          map( (result) => {
            let newPost = this.transformPostData(result.post);
            const oldPostIndex = this.posts.findIndex( (post: any) => {
              return post.id === newPost.id;
            });
    
            this.posts[oldPostIndex].comments = newPost.comments
            this.postsSubject.next([...this.posts]);
            return true;
          })
        );
  }

  transformPostData(post: any): Post {
    const user = this.userService.transformUserData(post.user);
    return {
      id: post._id,
      user: user,
      content: post.content,
      imageUrl: post.imageUrl,
      likes: post.likes,
      comments: post.comments,
      createdAt: post.createdAt
    }
  }

  handleWebSocket(data: any) {
      // new post created
      if(data.action === 'create') {
        let newPost = this.transformPostData(data.post); 
        if (this.userService.user.id != newPost.user.id && !this.userProfileId) {
          this.posts.unshift(newPost);
          this.postsSubject.next([...this.posts]);
        } else if (this.userProfileId) {
          if (this.userService.user.id != newPost.user.id && this.userProfileId == newPost.user.id) {
            this.posts.unshift(newPost);
            this.postsSubject.next([...this.posts]);
          }
        }
        
        // update post
      } else if(data.action === 'update') {
        this.handleSocketPost(data.post);

        // delete post
      } else if(data.action === 'delete') {
          let deletedPost =this.transformPostData(data.post); 
          let index = this.posts.findIndex( (post: any) => {
            return post.id === deletedPost.id;
          });
          if (index >= 0 && this.userService.user.id !== deletedPost.user.id) {
            this.posts.splice(index,1);
            this.postsSubject.next([...this.posts]);
          }
      } else if(data.action === 'addLike' || data.action === 'deleteLike') {
        this.handleSocketPost(data.post);

      } else if(data.action === 'addComment' || data.action === 'deleteComment' || data.action === 'editComment') {
        this.handleSocketPost(data.post);
      }
  }

  handleSocketPost(post: any) {
    let updatedPost =this.transformPostData(post); 
    let index = this.posts.findIndex( (post: any) => {
      return post.id === updatedPost.id;
    });
    if (index >= 0) {
      this.posts[index] = updatedPost;
      this.postsSubject.next([...this.posts]);
    }
  }

  getUserId() {

  }


}
