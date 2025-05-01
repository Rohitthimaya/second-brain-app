import mongoose from "mongoose";

const linkSchema = new mongoose.Schema({
    hash: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }
})

const Link = mongoose.model("Link", linkSchema);
export default Link