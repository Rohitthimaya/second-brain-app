import mongoose, { Types } from "mongoose";

const tagSchema = new mongoose.Schema({
    title: { type: String, required: true, unique: true }
});

const Tag = mongoose.model("Tag", tagSchema);
export default Tag;