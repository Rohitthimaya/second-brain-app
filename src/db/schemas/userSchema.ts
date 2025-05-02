import mongoose from "mongoose";
import { boolean } from "zod";

const userSchemaDB = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    shared: { type: Boolean, required: true  }
})

const User = mongoose.model("User", userSchemaDB);
export default User;