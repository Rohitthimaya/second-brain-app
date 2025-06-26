import mongoose, { Types } from "mongoose";
import { boolean } from "zod";

export interface IUser extends Document {
  username: string;
  password?: string;
  googleId?: string;
  shared: boolean;
  _id: Types.ObjectId;
}

const userSchemaDB = new mongoose.Schema<IUser>({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: false },
    shared: { type: Boolean, required: true  },
    googleId: { type: String, unique: true, sparse: true },
})

const User = mongoose.model<IUser>("User", userSchemaDB);
export default User;