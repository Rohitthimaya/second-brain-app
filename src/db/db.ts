import mongoose from "mongoose";
import * as dotenv from "dotenv";

export const connectDB = async () => {
    try {
        dotenv.config();
        const conn = await mongoose.connect(`${process.env.DB_CONN_STRING}`);
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Error: ${error}`);
        process.exit(1); // Exit process with failure
    }
};
