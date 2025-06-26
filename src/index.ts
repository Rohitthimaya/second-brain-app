import express from "express";
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
import { YoutubeTranscript } from "youtube-transcript";
import cors from "cors";

dotenv.config();

const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());


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

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype !== 'application/pdf') {
            return cb(null, false);
        }
        cb(null, true);
    }
});

app.post("/pdf/index", upload.single('file'), async (req, res) => {
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

app.post("/query", async (req, res) => {
    try {
        const { query } = req.body;

        if (!query) {
            res.status(400).json({ message: "Query required" });
        }

        // Step 1: Get embedding of query
        const response = await axios.post("http://127.0.0.1:5000/embed", {
            texts: [query]
        });

        const queryEmbedding = response.data.embeddings[0];
        console.log("Query embedding:", queryEmbedding);

        // Step 2: Search Milvus for similar chunks
        const searchResult = await client.search({
            collection_name: "embeddings",
            vector: queryEmbedding,
            limit: 5,
            output_fields: ["text", "title"],
            params: {
                anns_field: "vector",
                topk: "5",
                metric_type: "COSINE", // or "IP" or "COSINE"
                params: JSON.stringify({ nprobe: 10 }),
            },
        });


        const title = searchResult.results[0].title;
        console.log(title)

        const relevantText = searchResult.results.map(hit => hit.text);
        const context = relevantText.join("\n\n");

        console.log("Search Result: " + JSON.stringify(searchResult));
        console.log("Query received:", query);
        console.log("Top context chunks:\n", context);

        // Step 3: Ask LLaMA 3 via Ollama
        const llamaResponse = await axios.post("http://localhost:11434/api/generate", {
            model: "llama3",
            prompt: `Use the following context to answer the question.\n\nContext:\n${context}\n\nQuestion: ${query}`,
            stream: false
        });

        const answer = llamaResponse.data.response;

        res.json({
            answer,
            title,
            context: relevantText
        });

    } catch (error) {
        console.error("Error during query handling:", error);
        res.status(500).json({ message: "Something went wrong!" });
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

app.post("/api/v1/content", authenticateToken, async (req, res) => {
    try {
        const { user } = req as AuthenticatedRequest;

        const content = {
            type: req.body.type,
            link: req.body.link,
            title: req.body.title,
            tags: req.body.tags,
            userId: user?.id
        };

        const parsedContent = contentSchema.safeParse(content);

        if (!parsedContent.success) {
            res.status(400).json({
                error: parsedContent.error.flatten().fieldErrors,
            });
            return
        }

        const contentAdded = await Content.create(content);
        if (!contentAdded) {
            res.status(500).json({ message: "Failed to save content." });
            return
        }

        if (content.type === "tweet") {
            const tweetId = extractTweetId(content.link);
            if (!tweetId) {
                res.status(400).json({ message: "Invalid tweet URL" });
                return
            }

            const { textChunks } = await fetchSingleTweetContent(tweetId);
            const CHUNK_SIZE = 100;
            const allChunks: string[] = [];

            for (const text of textChunks) {
                const words = text.split(/\s+/);
                for (let i = 0; i < words.length; i += CHUNK_SIZE) {
                    allChunks.push(words.slice(i, i + CHUNK_SIZE).join(" "));
                }
            }

            const embeddingRes = await axios.post("http://127.0.0.1:5000/embed", {
                texts: allChunks
            });

            const embeddings = embeddingRes.data.embeddings;

            const records = allChunks.map((text, i) => ({
                text,
                vector: embeddings[i],
                title: content.title
            }));

            await client.insert({
                collection_name: "embeddings",
                data: records
            });

        } else if (content.type === "youtube") {
            const videoIdMatch = content.link.match(/(?:v=|\/|be\/|embed\/)([0-9A-Za-z_-]{11})/);
            const videoId = videoIdMatch?.[1];

            if (!videoId) {
                console.error("❌ Invalid YouTube URL:", content.link);
                res.status(400).json({ message: "Invalid YouTube URL" });
                return
            }

            try {
                console.log("📺 Fetching transcript from Supadata for videoId:", videoId);

                const transcriptRes = await axios.get(`https://api.supadata.ai/v1/youtube/transcript?videoId=${videoId}`, {
                    headers: {
                        'x-api-key': process.env.SUPA_YOUTUBE_API
                    }
                });
                const transcriptData = transcriptRes.data;

                if (!transcriptData || !Array.isArray(transcriptData.content) || transcriptData.content.length === 0) {
                    console.warn("⚠️ Supadata returned empty transcript.");
                    res.status(404).json({ message: "Transcript not available for this video." });
                    return
                }

                const fullText = transcriptData.content.map((entry: { text: any; }) => entry.text).join(" ");

                const words = fullText.split(/\s+/);
                const chunkSize = 1000;
                const chunks: string[] = [];

                for (let i = 0; i < words.length; i += chunkSize) {
                    chunks.push(words.slice(i, i + chunkSize).join(" "));
                }

                const embedRes = await axios.post("http://127.0.0.1:5000/embed", {
                    texts: chunks
                });

                const chunkEmbeddings = embedRes.data.embeddings;

                const records = chunks.map((chunk, idx) => ({
                    text: chunk,
                    vector: chunkEmbeddings[idx],
                    title: content.title
                }));

                await client.insert({
                    collection_name: "embeddings",
                    data: records
                });

            } catch (err) {
                console.error("❌ Supadata fetch failed:", (err as any)?.response?.data || err);
                res.status(500).json({ message: "Failed to fetch transcript from Supadata." });
                return
            }
        }

        res.status(200).json({ contentAdded, message: `${content.type} indexed and stored.` });

    } catch (error) {
        console.error("Error in /api/v1/content:", error);
        res.status(500).json({ error: "Something went wrong during content indexing." });
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
        const deleted = await Content.deleteOne({ _id: contentId, userId: user?.id })
        if (deleted) {
            res.status(200).json({ message: "Content Deleted" });
            return
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
})

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
    console.log(`App running on port: ${3000}`)
})