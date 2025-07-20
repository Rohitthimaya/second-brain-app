import mongoose, { Types } from "mongoose";

enum ContentTypes {
    "document",
    "tweet",
    "youtube",
    "link",
    "image",
    "video",
    "article",
    "audio",
    "pdf",
    "docx",
    "pptx",
    "note"
}

const chatMessageSchema = new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true }
}, { _id: false }); // no need for individual _id on each message

const chatHistorySchema = new mongoose.Schema({
    userId: { type: Types.ObjectId, ref: 'User', required: true },
    type: {type:String, enum:ContentTypes, required:true},
    contentLink: { type: String, required: true },
    title: { type: String, required: true },
    chats: { type: [chatMessageSchema], required: true }
}, { timestamps: true }); // adds createdAt and updatedAt

const ChatHistory = mongoose.model("ChatHistory", chatHistorySchema);
export default ChatHistory;
