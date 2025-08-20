import express, { Request, Response } from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import mongoose, { Document, Schema } from "mongoose";
import dotenv from "dotenv";
import Customer from "./models/customer";
import { QR } from "./models/qrs";
import { Scheme } from "./models/scheme";

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
    cors({
        credentials: true,
        origin: process.env.CLIENT_URL || "http://localhost:3000",
    })
);

// Constants
const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET || "";

// Connect to MongoDB
const connectDB = async (): Promise<void> => {
    try {
        const mongoUri = process.env.MONGODB_URI || "" ;
        await mongoose.connect(mongoUri);
        console.log("Connected to MongoDB");
    } catch (error) {
        console.error("MongoDB connection error:", error);
        process.exit(1);
    }
};

// JWT payload interface
interface JWTPayload {
    username: string;
    id: string;
}

//##################################################################################################################
// Register endpoint
app.post("/register", async (req: Request, res: Response): Promise<void> => {
    const { name, city, username, password }: { 
        name: string; 
        city: string; 
        username: string; 
        password: string; 
    } = req.body;
    
    try {
        const customerDoc = await Customer.create({
            name,
            city,
            username,
            password: bcrypt.hashSync(password, salt),
            points: 0
        });
        
        // Generate JWT token for the newly registered customer
        const payload: JWTPayload = {
            username: customerDoc.username,
            id: customerDoc.id.toString()
        };
        
        jwt.sign(payload, secret, { expiresIn: "7d" }, (err, token) => {
            if (err) {
                res.status(500).json({ error: "Token generation failed" });
                return;
            }
            
            res.cookie("token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            }).json({
                token: token
            });
        });
        
    } catch (err: any) {
        if (err.code === 11000) {
            // Check which field caused the duplicate error
            if (err.keyPattern?.username) {
                res.status(400).json({ error: "Username already exists" });
            } else {
                res.status(400).json({ error: "Duplicate entry found" });
            }
        } else {
            res.status(400).json({ error: err.message || "Registration failed" });
        }
    }
});

// Login endpoint
app.post("/login", async (req: Request, res: Response): Promise<void> => {
    try {
        const { username, password }: { username: string; password: string } = req.body;
        
        const customerDoc = await Customer.findOne({ username });
        
        if (!customerDoc) {
            res.status(400).json({ error: "Customer not found" });
            return;
        }
        
        const passOk = bcrypt.compareSync(password, customerDoc.password);
        
        if (passOk) {
            // Customer logged in successfully
            const payload: JWTPayload = {
                username: customerDoc.username,
                id: customerDoc.id.toString()
            };
            
            jwt.sign(payload, secret, { expiresIn: "7d" }, (err, token) => {
                if (err) {
                    res.status(500).json({ error: "Token generation failed" });
                    return;
                }
                
                res.cookie("token", token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                }).json({
                    token: token
                });
            });
        } else {
            res.status(400).json({ error: "Wrong credentials" });
        }
    } catch (err: any) {
        res.status(500).json({ error: err.message || "Login failed" });
    }
});

// Logout endpoint
app.post("/logout", (req: Request, res: Response): void => {
    res.cookie("token", "", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 0,
    }).json({ message: "Logged out successfully" });
});

// Get customer profile endpoint
app.get("/profile", async (req: Request, res: Response): Promise<void> => {
    try {
        const token = req.cookies.token;
        
        if (!token) {
            res.status(401).json({ error: "Access token required" });
            return;
        }

        const decoded = jwt.verify(token, secret) as JWTPayload;
        const customer = await Customer.findById(decoded.id).select('-password');
        
        if (!customer) {
            res.status(404).json({ error: "Customer not found" });
            return;
        }

        res.json(customer);
    } catch (err: any) {
        res.status(403).json({ error: "Invalid or expired token" });
    }
});

//##################################################################################################################
app.get('/api/schemes', async (req: Request, res: Response): Promise<void> => {
    try {
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;
        const skip = (page - 1) * limit;

        // Get total count for pagination
        const totalSchemes = await Scheme.countDocuments();

        // Get schemes with pagination
        const schemes = await Scheme.find()
            .sort({ createdAt: -1 }) // Sort by newest first
            .skip(skip)
            .limit(limit);

        const totalPages = Math.ceil(totalSchemes / limit);

        res.status(200).json({
            success: true,
            data: schemes,
            pagination: {
                currentPage: page,
                totalPages,
                totalSchemes,
                hasNextPage: page < totalPages,
                hasPrevPage: page > 1
            }
        });

    } catch (error: any) {
        console.error('Error fetching schemes:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: any) => {
    console.error(err.stack);
    res.status(500).json({ error: "Something went wrong!" });
});

// Start server
const PORT = process.env.PORT || 4000;

const startServer = async (): Promise<void> => {
    await connectDB();
    
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
};

startServer().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
});