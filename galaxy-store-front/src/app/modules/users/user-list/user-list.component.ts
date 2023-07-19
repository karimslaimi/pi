import {Component, OnInit} from '@angular/core';
import {UserService} from "../../../core/services/user.service";

@Component({
  selector: 'app-user-list',
  templateUrl: './user-list.component.html',
  styleUrls: ['./user-list.component.scss']
})
export class UserListComponent implements OnInit{
  data:any[] = [];
  filterText = '';
  columns = [
    { prop: '_id', name: 'id' },
    { prop: 'firstName', name: 'firstName' },
    { prop: 'lastName', name: 'lastName' },
    { prop: 'username', name: 'username' },
    { prop: 'email', name: 'email' },
  ];

  constructor(private userService:UserService) {
  }

  ngOnInit() {
    this.fetchData();
  }

  fetchData(){
    this.userService.getAllUsers().subscribe({
      next:(response:any)=>{
        console.log(response);
        this.data = response
      }
    })
  }

  filterItems(event:any) {
    if (this.data.length == 0 || this.filterText == ''){
      this.fetchData();
    }
    const filterValue = this.filterText.toLowerCase().trim();

    this.data = this.data.filter(item =>
      item.username.toLowerCase().includes(filterValue) ||
      item.email.toString().includes(filterValue)
    );
  }

  deleteRow(row:any) {
    this.userService.deleteUser(row._id).subscribe({
      next:()=>{
        this.fetchData();
      },
      error:(e)=>{
        console.log(e);
        alert("an error occured");
      }
    })

  }

  confirmAccount(row:any){

    if (row.statusUser !== 'confirmé'){
      this.userService.confirmAccount(row._id).subscribe({
        next:()=>{
          this.fetchData();
        },
        error:(e)=>{
          console.log(e);
          alert("an error occured");
        }
      });
    }

  }

  handleBlock(row:any){

    if (row.statusCompte == 'actif'){
      this.userService.blockAccount(row._id).subscribe({
        next:()=>{
          this.fetchData();
        },
        error:(e)=>{
          console.log(e);
          alert("an error occured");
        }
      });
    }else{
      this.userService.unblockAccount(row._id).subscribe({
        next:()=>{
          this.fetchData();
        },
        error:(e)=>{
          console.log(e);
          alert("an error occured");
        }
      })
    }
  }
}
