import express from "express";
import { userSchema, userSchemaTs } from "./validations/uservalidation";
import { connectDB } from "./db/db"
import User from "./db/schemas/userSchema";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
import { authenticateToken, AuthenticatedRequest } from "./middleware/middleware"
import { contentSchema } from "./validations/contentvalidation";
import linkSchema from "./db/schemas/linkSchema"
import Link from "./db/schemas/linkSchema";
import { random } from "./utils";
import Content from "./db/schemas/contentSchema";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

dotenv.config();
connectDB()

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

app.post("/api/v1/content", authenticateToken, async (req: AuthenticatedRequest, res) => {
    try {
        const user = req.user;
        const content = {
            type: req.body.type,
            link: req.body.link,
            title: req.body.title,
            tags: req.body.tags,
            userId: user?.id
        }
        const parsedContent = contentSchema.safeParse(content)

        if (!parsedContent.success) {
            res.status(400).json({
                error: parsedContent.error.flatten().fieldErrors,
            });
            return;
        }

        const contentAdded = await Content.create(content)

        if (contentAdded) {
            res.status(200).json({ contentAdded });
            return
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
});

app.get("/api/v1/content", authenticateToken, async (req: AuthenticatedRequest, res) => {
    try {
        const user = req.user;

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

app.delete("/api/v1/content", authenticateToken, async (req: AuthenticatedRequest, res) => {
    try {
        const contentId = req.body.contentId;
        const deleted = await Content.deleteOne({ _id: contentId, userId: req.user?.id })
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

app.post("/api/v1/brain/share", authenticateToken, async (req: AuthenticatedRequest, res) => {
    try {
        const share = req.body.share;
        if (share) {
            const existing = await Link.findOne({
                userId: req.user?.id
            })

            if(existing){
                res.status(200).json({
                    hash: existing.hash
                })
                return
            }
            
            const hash = random(10)

            await Link.create({
                userId: req.user?.id,
                hash: hash
            })

            res.status(200).json({ message: "/share/" + hash })
            return
        } else {
            await Link.deleteOne({ userId: req.user?.id })
            res.status(200).json({ message: "Share disabled!" })
            return
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
})

app.get("/api/v1/brain/:shareLink", authenticateToken, async (req: AuthenticatedRequest, res) => {
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