import express from "express";
import mammoth from "mammoth";
import { userSchema, userSchemaTs } from "./validations/uservalidation";
import { connectDB } from "./db/db"
import User, { IUser } from "./db/schemas/userSchema";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
import { authenticateToken, AuthenticatedRequest } from "./middleware/middleware"
import { contentSchema } from "./validations/contentvalidation";
import linkSchema from "./db/schemas/linkSchema"
import Link from "./db/schemas/linkSchema";
import { random } from "./utils";
import Content from "./db/schemas/contentSchema";
import multer from "multer";
import path from "path";
import fs from "fs";
import pdfParse from 'pdf-parse';
import axios from "axios";
import { MilvusClient, DataType } from '@zilliz/milvus2-sdk-node';
import { TwitterApi } from 'twitter-api-v2';
import AWS from "aws-sdk";
// import { YoutubeTranscript } from "youtube-transcript";
import cors from "cors";
import { text } from "body-parser";

dotenv.config();

const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
});


connectDB()

// Replace with your Bearer Token from https://developer.twitter.com
const twitterClient = new TwitterApi(`${process.env.Bearer_Token}`);

const address = `${process.env.address}`;
const token = `${process.env.token}`
// connect to milvus
const client = new MilvusClient({ address, token });

app.post('/auth/google', async (req, res) => {
    const { idToken } = req.body;

    try {
        const ticket = await googleClient.verifyIdToken({
            idToken,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { email, sub: googleId } = payload;

        if (!email) {
            res.status(400).json({ message: "Email is required from Google token." });
            return
        }

        // Check if user exists
        let user = await User.findOne({ username: email });

        // If not, create new user with no password
        if (!user) {
            user = await User.create({
                username: email,
                password: null, // Or you can omit this field
                shared: false,
                googleId, // Optional: store for reference
                // name      // Optional: store full name
            });
        }

        const token = jwt.sign({ id: user._id, username: user.username }, `${process.env.SECRET_KEY}`, { expiresIn: '1d' })

        res.status(200).json({ message: "Authentication successful", token: token });

    } catch (error) {
        console.error("Error verifying ID token:", error);
        res.status(401).json({ message: "Authentication failed" });
    }
});


// Sign Up
app.post("/api/v1/signup", async (req, res) => {
    try {
        const parsedObj = userSchema.safeParse(req.body);

        if (!parsedObj.success) {
            res.status(400).json({
                error: parsedObj.error.flatten().fieldErrors,
            });
            return;
        }

        const { username, password } = parsedObj.data;

        const userExist = await User.findOne({ username });

        if (userExist) {
            res.status(409).json({ message: "User already exists!" });
            return
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            username,
            password: hashedPassword,
            shared: false
        });

        const token = jwt.sign({ id: user._id, username: user.username }, `${process.env.SECRET_KEY}`, { expiresIn: '1d' })

        if (user) {
            res.status(201).json({ message: "User created successfully.", token });
            return
        }

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
});

// Sign In
app.post("/api/v1/signin", async (req, res) => {
    try {
        const parsedObj = userSchema.safeParse(req.body);

        if (!parsedObj.success) {
            res.status(400).json({
                error: parsedObj.error.flatten().fieldErrors,
            });
            return;
        }

        const { username, password } = parsedObj.data;

        const userExist = await User.findOne({ username });

        console.log(userExist)

        if (!userExist) {
            res.status(401).json({ message: "User Not Found" });
            return;
        }

        if (!userExist.password) {
            res.status(500).json({ message: "User password is missing." });
            return;
        }
        const isPasswordCorrect = await bcrypt.compare(password, userExist.password);

        if (!isPasswordCorrect) {
            res.status(401).json({ message: "Invalid credentials" });
            return;
        }

        const token = jwt.sign({ id: userExist._id, username: userExist.username }, `${process.env.SECRET_KEY}`, { expiresIn: '1d' })

        res.status(200).json({ message: "User Sign In", token });
        return;

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
})

// Configure multer to store uploaded PDFs in /uploads folder
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath);
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, `${uniqueSuffix}-${file.originalname}`);
    }
});

// const upload = multer({
//     storage: storage,
//     fileFilter: (req, file, cb) => {
//         if (file.mimetype !== 'application/pdf') {
//             return cb(null, false);
//         }
//         cb(null, true);
//     }
// });
const upload = multer({ storage: multer.memoryStorage() });


app.post("/pdf/index", authenticateToken, upload.single('file'), async (req, res) => {
    const { user } = req as AuthenticatedRequest;

    // TODO1: Get the pdf file
    const pdfFilePath = req.file?.path;
    const pdfFileName = req.file?.filename;

    // TODO2: Convert entire feedback into text (pdf parse)
    if (!pdfFilePath || !pdfFileName) {
        res.status(400).json({ message: 'No PDF file uploaded' });
        return;
    }

    const dataBuffer = fs.readFileSync(pdfFilePath);
    const pdfData = await pdfParse(dataBuffer);
    const extractedText = pdfData.text;
    console.log("Extracted text:", extractedText);

    // TODO3: Convert pdf file text into small small chunks
    const words = extractedText.split(/\s+/)
    const chunkSize = 1000;
    const chunks = [];

    for (let i = 0; i < words.length; i += chunkSize) {
        const chuck = words.slice(i, i + chunkSize).join(' ');
        chunks.push(chuck)
    }

    // TODO4: Convert each chunck to vector embedding [We will be using SentenceTransformer (python)]
    // const response = await axios.post(
    //     "https://api.cohere.ai/v1/embed",
    //     {
    //         texts: chunks,
    //         model: "embed-english-v3.0",
    //         input_type: "search_document"
    //     },
    //     {
    //         headers: {
    //             "Authorization": `Bearer ${process.env.COHERE_API_KEY}`,
    //             "Content-Type": "application/json"
    //         }
    //     }
    // ); 
    
    const response = await axios.post("http://127.0.0.1:5000/embed", {
        texts: chunks
    });

    const chunkEmbeddings = response.data.embeddings;

    chunkEmbeddings.forEach((embedding: any, index: any) => {
        console.log(`Embedding for chunk ${index}:`, embedding);
    });

    // TODO5: Store vector embedding in vector database [Millivus]
    // Prepare records
    const records = chunks.map((chunk, idx) => ({
        text: chunk,
        vector: chunkEmbeddings[idx],
        userId: user?.id
    }));

    // Insert into Milvus
    const result = await client.insert({
        collection_name: "embeddings",
        data: records,
    });

    console.log(result)

    // Delete the file
    if (pdfFilePath) {
        fs.unlinkSync(pdfFilePath);
        console.log("file deleted")
    }
    res.json({
        message: "Success"
    })
    return
})

app.post("/query", authenticateToken, async (req, res) => {
    try {
        const { query } = req.body;
        const { user } = req as AuthenticatedRequest;

        if (!query) {
            res.status(400).json({ message: "Query required" });
        }

        // Step 1: Get embedding of query
        // const response = await axios.post(
        //     "https://api.cohere.ai/v1/embed",
        //     {
        //         texts: [query],
        //         model: "embed-english-v3.0",
        //         input_type: "search_document"
        //     },
        //     {
        //         headers: {
        //             "Authorization": `Bearer ${process.env.COHERE_API_KEY}`,
        //             "Content-Type": "application/json"
        //         }
        //     }
        // );

        const response = await axios.post("http://127.0.0.1:5000/embed", {
            texts: [query]
        });
        
        const queryEmbedding = response.data.embeddings[0];
        console.log("Query embedding:", queryEmbedding);

        // Step 2: Search Milvus for similar chunks
        const searchResult = await client.search({
            collection_name: "embeddings",
            vector: queryEmbedding,
            limit: 3,
            output_fields: ["text", "title"],
            filter: `userId == "${user?.id}"`,
            params: {
                anns_field: "vector",
                topk: 3,
                metric_type: "COSINE", // or "IP" or "COSINE"
                params: JSON.stringify({ nprobe: 10 }),
            },
        });

        console.log(searchResult)

        const title = searchResult.results[0].title;

        const relevantText = searchResult.results.map(hit => hit.text);
        const context = relevantText.join("\n\n");

        console.log("Search Result: " + JSON.stringify(searchResult));
        console.log("Query received:", query);
        console.log("Top context chunks:\n", context);

        // Step 3: Ask LLaMA 3 via Ollama
        const aimlResponse = await axios.post("http://localhost:11434/api/generate", {
            model: "llama3",
            prompt: `Use the following context to answer the question.\n\nContext:\n${context}\n\nQuestion: ${query}`,
            stream: false
        });

        const answer = aimlResponse.data.response;

        const responseObj = await Content.find({ title })
        const responseLink = responseObj[0].link
        const type = responseObj[0].type
        // const aimlResponse = await axios.post(
        //     "https://api.aimlapi.com/v1/chat/completions",
        //     {
        //         model: "gpt-3.5-turbo",
        //         messages: [
        //             {
        //                 role: "user",
        //                 content: `Use the following context to answer the question.\n\nContext:\n${context}\n\nQuestion: ${query}`
        //             }
        //         ],
        //         max_tokens: 500,
        //         temperature: 0.7
        //     },
        //     {
        //         headers: {
        //             Authorization: `Bearer ${process.env.AIMLAPI_KEY}`,
        //             "Content-Type": "application/json"
        //         }
        //     }
        // );
        
        // const answer = aimlResponse.data.choices[0].message.content;
        
        // console.log(JSON.stringify(aimlResponse.data, null, 2));       

        res.json({
            answer,
            title,
            context: relevantText,
            responseLink,
            type
        });

    } catch (error) {
        console.error("Error during query handling:", error);
        res.status(500).json({ message: "Something went wrong!" });
    }
});

app.post("/ask-doc", authenticateToken, async (req, res) => {
    try {
        const { question, link: title } = req.body;
        const { user } = req as AuthenticatedRequest;

        if (!question || !title) {
            res.status(400).json({ message: "Question and title are required" });
            return
        }

        // Step 1: Query Milvus with a filter to get all matching text chunks
        const searchResult = await client.query({
            collection_name: "embeddings",
            output_fields: ["text"],
            filter: `title == "${title}" && userId == "${user?.id}"`,
        });

        if (!searchResult) {
            res.status(404).json({ message: "No context found for this document" });
            return
        }

        console.log(searchResult)

        const context = searchResult.data.map(item => item.text).join("\n\n");

        // Step 2: Generate answer using Ollama or LLM of your choice
        const aimlResponse = await axios.post("http://localhost:11434/api/generate", {
            model: "llama3",
            prompt: `Use the following context to answer the question.\n\nContext:\n${context}\n\nQuestion: ${question}`,
            stream: false
        });

        const answer = aimlResponse.data.response;

        // Optional: Retrieve content metadata from MongoDB
        // const doc = await Content.findOne({ title });
        // const responseLink = doc?.link || null;
        // const type = doc?.type || null;

        res.json({
            answer,
            // title,
            // context: searchResult.map(r => r.text),
            // responseLink,
            // type
        });

    } catch (error) {
        console.error("Error in /ask-doc:", error);
        res.status(500).json({ message: "Server error" });
    }
});

function extractTweetId(url: string): string | null {
    const match = url.match(/status\/(\d+)/);
    return match ? match[1] : null;
}

async function fetchSingleTweetContent(tweetId: string): Promise<{ textChunks: string[], metadata: any[] }> {
    const tweet = await twitterClient.v2.singleTweet(tweetId, {
        "tweet.fields": ["text", "created_at", "id"]
    });

    const text = tweet.data.text;

    // Optionally chunk the tweet text if it's very long
    const words = text.split(/\s+/);
    const chunkSize = 100; // words per chunk
    const chunks: string[] = [];

    for (let i = 0; i < words.length; i += chunkSize) {
        chunks.push(words.slice(i, i + chunkSize).join(" "));
    }

    const metadata = [{
        tweet_id: tweet.data.id,
        created_at: tweet.data.created_at,
        text: tweet.data.text
    }];

    return {
        textChunks: chunks,
        metadata
    };
}

function extractYouTubeId(url: string) {
    const match = url.match(/(?:v=|\/|be\/|embed\/)([0-9A-Za-z_-]{11})/);
    return match?.[1];
}

async function fetchYouTubeTranscript(videoId: string): Promise<string> {
    const res = await axios.get(`https://api.supadata.ai/v1/youtube/transcript?videoId=${videoId}`, {
        headers: { 'x-api-key': process.env.SUPA_YOUTUBE_API }
    });
    const entries = res.data?.content ?? [];
    return entries.map((e: { text: string }) => e.text).join(" ");
}

async function extractTextFromPdfBuffer(buffer: Buffer): Promise<string> {
    const data = await pdfParse(buffer);
    return data.text || "";
}

async function extractTextFromDocxBuffer(buffer: Buffer): Promise<string> {
    try {
        const result = await mammoth.extractRawText({ buffer });
        return result.value;
    } catch (err) {
        console.error("❌ Error extracting .docx text:", err);
        return "";
    }
}

async function indexChunks(
    texts: string[],   // array of full texts
    title: string,
    userId: string | undefined,
    contentId: string | any,
    chunkSize = 100
) {
    const allChunks: string[] = [];

    for (const text of texts) {      // loop over each full text string
        const words = text.split(/\s+/);
        for (let i = 0; i < words.length; i += chunkSize) {
            allChunks.push(words.slice(i, i + chunkSize).join(" "));
        }
    }

    // Now allChunks is an array of text chunks, ready to send

    // const embedRes = await axios.post(
    //     "https://api.cohere.ai/v1/embed",
    //     {
    //         texts: allChunks,
    //         model: "embed-english-v3.0",
    //         input_type: "search_document"
    //     },
    //     {
    //         headers: {
    //             "Authorization": `Bearer ${process.env.COHERE_API_KEY}`,
    //             "Content-Type": "application/json"
    //         }
    //     }
    // );

    const embedRes = await axios.post("http://127.0.0.1:5000/embed", {
        texts: allChunks
    });

    

    const embeddings = embedRes.data.embeddings;
    const records = allChunks.map((chunkText, idx) => ({
        text: chunkText,
        vector: embeddings[idx],
        title,
        userId,
        contentId
    }));

    await client.insert({ collection_name: "embeddings", data: records });
}


app.post("/api/v1/content", authenticateToken, upload.single("file"), async (req, res) => {
    try {
        const { user } = req as AuthenticatedRequest;
        const { title, type, link = "", tags = [] } = req.body;
        let finalLink = link;

        // Handle PDF upload
        if ((type === "pdf" || type === "docx" || type === "pptx") && req.file) {
            try {
                const s3Res = await s3.upload({
                    Bucket: `${process.env.S3_BUCKET_NAME}`,
                    Key: `pdfs/${Date.now()}_${req.file.originalname}`,
                    Body: req.file.buffer,
                    ContentType: req.file.mimetype,
                    ACL: "public-read"
                }).promise();

                finalLink = s3Res.Location;
            } catch (err) {
                console.error("❌ PDF upload failed:", err);
                res.status(500).json({ error: "PDF upload failed" });
                return
            }
        }else if(type == "audio" && req.file){
            try {
                const s3Res = await s3.upload({
                    Bucket: `${process.env.S3_BUCKET_NAME}`,
                    Key: `audios/${Date.now()}_${req.file.originalname}`,
                    Body: req.file.buffer,
                    ContentType: req.file.mimetype,
                    ACL: "public-read"
                  }).promise();
              
                  finalLink = s3Res.Location;
            } catch (error) {
                console.error("❌ audio upload failed:", error);
                res.status(500).json({ error: "PDF upload failed" });
                return
            }
        }

        const content = { title, type, link: finalLink, tags, userId: user?.id };
        console.log(content)
        const parsedContent = contentSchema.safeParse(content);
        if (!parsedContent.success) {
            res.status(400).json({ error: parsedContent.error.flatten().fieldErrors });
            return
        }

        const contentAdded = await Content.create(content);
        if (!contentAdded) {
            res.status(500).json({ message: "Failed to save content" });
            return
        }

        // Index based on content type
        switch (type) {
            case "tweet": {
                const tweetId = extractTweetId(finalLink);
                if (!tweetId){
                    res.status(400).json({ message: "Invalid tweet URL" });
                    return
                } 

                const { textChunks } = await fetchSingleTweetContent(tweetId);
                await indexChunks(textChunks, content.title, user?.id, contentAdded._id);
                break;
            }

            case "youtube": {
                const videoId = extractYouTubeId(finalLink);
                if (!videoId){
                    res.status(400).json({ message: "Invalid YouTube URL" });
                    return
                }

                const transcript = await fetchYouTubeTranscript(videoId);
                await indexChunks([transcript], content.title, user?.id, contentAdded._id, 1000);
                break;
            }

            case "pdf": {
                if (!req.file) {
                    res.status(400).json({ message: "No PDF file uploaded" });
                    return;
                }
                const pdfText = await extractTextFromPdfBuffer(req.file.buffer);
                await indexChunks([pdfText], content.title, user?.id, contentAdded._id, 1000);
                break;
            }
            case "docx": {
                if (!req.file) {
                    res.status(400).json({ message: "No DOCX file uploaded" });
                    return;
                }
            
                try {
                    const docxText = await extractTextFromDocxBuffer(req.file.buffer);
                    await indexChunks([docxText], content.title, user?.id, contentAdded._id, 1000);
                } catch (err) {
                    console.error("❌ DOCX processing failed:", err);
                    res.status(500).json({ error: "DOCX upload or processing failed" });
                    return;
                }
            
                break;
            }          
            case "audio": {
                if (!req.file) {
                  res.status(400).json({ message: "No audio file uploaded" });
                  return;
                }
                try {

                  // process audio file, e.g., send to transcription service
                  // const transcript = await yourTranscriptionFunction(req.file.buffer);
                  // await indexChunks([transcript], content.title, user?.id, contentAdded._id);
              
                } catch (err) {
                  console.error("❌ Audio upload failed:", err);
                  res.status(500).json({ error: "Audio upload failed" });
                  return;
                }
              
                break;
              }
        }

        res.status(200).json({ message: "Content indexed and stored", content: contentAdded });
        return
    } catch (error) {
        console.error("❌ Error in content route:", error);
        res.status(500).json({ error: "Something went wrong" });
    }
});


app.get("/api/v1/content", authenticateToken, async (req, res) => {
    try {
        // const user = req.user;
        const user = (req as AuthenticatedRequest).user;

        const userContent = await Content.find({ userId: user?.id }).populate("userId", "username")

        if (userContent) {
            res.status(200).json({ userContent });
            return
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
})

app.delete("/api/v1/content", authenticateToken, async (req, res) => {
    try {
        const { user } = req as AuthenticatedRequest;
        const contentId = req.body.contentId;

        const deleted = await Content.deleteOne({ _id: contentId, userId: user?.id });

        if (deleted.deletedCount === 1) {
            await client.deleteEntities({
                collection_name: "embeddings",
                filter: `contentId == "${contentId}"`
            });

            res.status(200).json({ message: "Content and vectors deleted successfully." });
            return
        } else {
            res.status(404).json({ message: "Content not found or unauthorized." });
            return
        }
    } catch (error) {
        console.error("Error deleting content:", error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
});


app.post("/api/v1/brain/share", authenticateToken, async (req, res) => {
    try {
        const { user } = req as AuthenticatedRequest;
        const share = req.body.share;
        if (share) {
            const existing = await Link.findOne({
                userId: user?.id
            })

            if (existing) {
                res.status(200).json({
                    hash: existing.hash
                })
                return
            }

            const hash = random(10)

            await Link.create({
                userId: user?.id,
                hash: hash
            })

            res.status(200).json({ message: "/share/" + hash })
            return
        } else {
            await Link.deleteOne({ userId: user?.id })
            res.status(200).json({ message: "Share disabled!" })
            return
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
})

app.get("/api/v1/brain/:shareLink", authenticateToken, async (req, res) => {
    try {
        const hash = req.params.shareLink;

        const link = await Link.findOne({
            hash
        })

        if (!link) {
            res.status(411).json({ message: "Incorrect Url" })
            return;
        }

        const content = await Content.find({
            userId: link.userId
        })

        const user = await User.find({
            _id: link.userId
        })

        res.status(200).json({
            username: user,
            content: content
        })
        return
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
})

app.listen(3000, () => {
    console.log(`App running on port: ${8080}`)
})
