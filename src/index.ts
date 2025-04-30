import bodyParser from "body-parser";
import express from "express";
import { userSchema, userSchemaTs } from "./validations/validations";
import {connectDB} from "./db/db"
import User from "./db/userSchema";
import bcrypt from "bcrypt";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  
      res.status(201).json({ message: "User created successfully." });
      return 
  
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Something went wrong." });
      return 
    }
  });
  

app.listen(3000, () => {
    console.log(`App running on port: ${3000}`)
})