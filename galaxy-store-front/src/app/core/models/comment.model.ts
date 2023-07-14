import { User } from "./user.model";
export interface Comment {
    id: string;
    user: User;
    content: string;
    createdAt: any;
    updatedAt: any;
}