import { PipeTransform, Pipe } from '@angular/core';
@Pipe({
  name: 'roomUsername',
})
export class RoomUsername implements PipeTransform {
  transform(value: string): string {
    let splitUsername = value.split('-');
    if (splitUsername.length > 1) {
      if (splitUsername[1] === localStorage.getItem('username')) {
        return value.split('-')[2];
      } else {
        return value.split('-')[1];
      }
    } else {
      return value;
    }
  }
}
