import mongoose, { Types } from "mongoose";

enum ContentTypes {
    "document",
    "tweet",
    "youtube",
    "link",
    "image",
    "video",
    "article",
    "audio"
}

const contentSchemaDB = new mongoose.Schema({
    type: {type:String, enum:ContentTypes, required:true},
    link: {type: String, required: true},
    title: {type: String, required: true},
    tags: [{type: Types.ObjectId, ref: 'Tag'}],
    userId: {type: Types.ObjectId, ref: 'User', required:true}
})

const Content = mongoose.model("Content", contentSchemaDB);
export default Content;