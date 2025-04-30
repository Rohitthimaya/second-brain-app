import bodyParser from "body-parser";
import express from "express";
import { userSchema, userSchemaTs } from "./validations/validations";
import { connectDB } from "./db/db"
import User from "./db/userSchema";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
import {authenticateToken, AuthenticatedRequest} from "./middleware/middleware"

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
        });

        const token = jwt.sign(user, `${process.env.SECRET_KEY}`, {expiresIn: '1d'})

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

        const token = jwt.sign({id: userExist._id, username: userExist.username}, `${process.env.SECRET_KEY}`, {expiresIn: '1d'})

        res.status(200).json({ message: "User Sign In", token });
        return;

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
        return
    }
})

app.post("/api/v1/content", authenticateToken, (req: AuthenticatedRequest, res) => {
    const user = req.user;
    res.status(200).json({ message: `Hello, ${user?.username}` });
  });
  

app.listen(3000, () => {
    console.log(`App running on port: ${3000}`)
})