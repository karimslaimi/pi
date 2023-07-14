import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { environment } from "src/environments/environment";
import { UserService } from "./user.service";

@Injectable({
    providedIn: 'root'
})

export class SessionsService {
    private url: string = environment.API_URL + "/api/session";

    constructor(private http: HttpClient, private userService: UserService) {}

    getSessions() {
        return this.http.get<any>(this.url);
    }

    getSessionByRoom(room: string) {
        return this.http.get<any>(this.url + `/${room}`);
    }

    createSession(session: any) {
        return this.http.post<any>(this.url, session);
    }

    updateSession(room: string, session: any) {
        return this.http.put<any>(this.url + `/${room}`, session);
    }

    deleteSession(room: string) {
        return this.http.delete<any>(this.url + `/${room}`);
    }
}