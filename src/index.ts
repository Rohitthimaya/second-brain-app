import bodyParser from "body-parser";
import express from "express";
import { userSchema, userSchemaTs } from "./validations/validations";
import {connectDB} from "./db/db"
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());

connectDB()

// Sign up
app.post("/api/v1/signup", (req, res) => {
    // zod validations
    const parsedObj = userSchema.safeParse(req.body);

    if (!parsedObj.success) {
        res.status(411).json({
            error: parsedObj.error.flatten().fieldErrors
        });
    }

    const updatedBody: userSchemaTs = req.body

    // Check if user exist = middleware
    // Create user and add into mongo db
    // provide jwt token
    // redirect to main page
})

app.listen(3000, () => {
    console.log(`App running on port: ${3000}`)
})