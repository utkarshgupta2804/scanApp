import express, { Request, Response } from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import mongoose, { Document, Schema } from "mongoose";
import dotenv from "dotenv";
import Customer from "./models/customer";
import { QRBatch, IQRBatch } from "./models/qrs";
import { Scheme } from "./models/scheme";
import path from 'path';

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// IMPORTANT: Add static file serving for uploads
app.use('/uploads', express.static(path.resolve('uploads')));

app.use(
    cors({
        credentials: true,
        origin: process.env.CLIENT_URL,
    })
);

// Constants
const secret = process.env.JWT_SECRET || "";

// Connect to MongoDB
const connectDB = async (): Promise<void> => {
    try {
        const mongoUri = process.env.MONGODB_URI || "";
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

const authenticateToken = (req: Request, res: Response, next: any) => {
    let token;

    if (req.headers.authorization) {
        const authHeader = req.headers.authorization.replace(/\s+/g, ' ').trim();
        if (authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7).trim();
        }
    } else if (req.cookies?.token) {
        token = req.cookies.token.trim();
    }

    if (!token) {
        return res.status(401).json({ error: "Access token required" });
    }

    try {
        const decoded = jwt.verify(token, secret) as JWTPayload;
        (req as any).user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ error: "Invalid or expired token" });
    }
};

//##################################################################################################################
// Register endpoint - Updated to store plain text passwords
app.post("/register", async (req: Request, res: Response): Promise<void> => {
    const { name, city, username, phone, email, password }: {
        name: string;
        city: string;
        username: string;
        phone: string;
        email?: string;
        password: string;
    } = req.body;

    try {
        // Validate required fields
        if (!name || !city || !username || !phone || !password) {
            res.status(400).json({ error: "Name, city, username, phone, and password are required" });
            return;
        }

        // Validate phone number format (10 digits)
        const phoneRegex = /^[0-9]{10}$/;
        if (!phoneRegex.test(phone)) {
            res.status(400).json({ error: "Please enter a valid 10-digit phone number" });
            return;
        }

        // Validate email format if provided
        if (email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                res.status(400).json({ error: "Please enter a valid email address" });
                return;
            }

            // Check if email already exists (only if email is provided)
            const existingEmail = await Customer.findOne({ email: email.toLowerCase() });
            if (existingEmail) {
                res.status(400).json({ error: "Email already exists" });
                return;
            }
        }

        // Check if phone already exists
        const existingPhone = await Customer.findOne({ phone });
        if (existingPhone) {
            res.status(400).json({ error: "Phone number already exists" });
            return;
        }

        // Check if username already exists
        const existingUsername = await Customer.findOne({ username: username.toLowerCase() });
        if (existingUsername) {
            res.status(400).json({ error: "Username already exists" });
            return;
        }

        const customerData: any = {
            name: name.trim(),
            city: city.trim(),
            username: username.toLowerCase().trim(),
            phone: phone.trim(),
            password: password.trim(), // Store password as plain text
            points: 0
        };

        // Add email only if provided
        if (email) {
            customerData.email = email.toLowerCase().trim();
        }

        const customerDoc = await Customer.create(customerData);

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
                token: token,
                message: "Registration successful"
            });
        });

    } catch (err: any) {
        if (err.code === 11000) {
            // Check which field caused the duplicate error
            if (err.keyPattern?.username) {
                res.status(400).json({ error: "Username already exists" });
            } else if (err.keyPattern?.email) {
                res.status(400).json({ error: "Email already exists" });
            } else if (err.keyPattern?.phone) {
                res.status(400).json({ error: "Phone number already exists" });
            } else {
                res.status(400).json({ error: "Duplicate entry found" });
            }
        } else {
            res.status(400).json({ error: err.message || "Registration failed" });
        }
    }
});

// Login endpoint - Can use email, username, or phone with plain text password comparison
app.post("/login", async (req: Request, res: Response): Promise<void> => {
    try {
        const { identifier, password }: { identifier: string; password: string } = req.body;

        if (!identifier || !password) {
            res.status(400).json({ error: "Email/username/phone and password are required" });
            return;
        }

        // Determine the type of identifier and create appropriate query
        let query: any;
        const trimmedIdentifier = identifier.trim();

        if (trimmedIdentifier.includes('@')) {
            // It's an email
            query = { email: trimmedIdentifier.toLowerCase() };
        } else if (/^[0-9]{10}$/.test(trimmedIdentifier)) {
            // It's a phone number
            query = { phone: trimmedIdentifier };
        } else {
            // It's a username
            query = { username: trimmedIdentifier.toLowerCase() };
        }

        const customerDoc = await Customer.findOne(query);

        if (!customerDoc) {
            res.status(400).json({ error: "User not found" });
            return;
        }

        // Compare passwords directly (plain text comparison)
        const passOk = password.trim() === customerDoc.password;

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
                    token: token,
                    message: "Login successful"
                });
            });
        } else {
            res.status(400).json({ error: "Wrong credentials" });
        }
    } catch (err: any) {
        res.status(500).json({ error: err.message || "Login failed" });
    }
});

// Update Profile endpoint
app.put("/profile", authenticateToken, async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user;
        const { name, city, email, phone }: {
            name?: string;
            city?: string;
            email?: string;
            phone?: string;
        } = req.body;

        const customer = await Customer.findById(user.id);

        if (!customer) {
            res.status(404).json({ error: "Customer not found" });
            return;
        }

        // Validate and update fields if provided
        if (name !== undefined) {
            if (!name.trim()) {
                res.status(400).json({ error: "Name cannot be empty" });
                return;
            }
            customer.name = name.trim();
        }

        if (city !== undefined) {
            if (!city.trim()) {
                res.status(400).json({ error: "City cannot be empty" });
                return;
            }
            customer.city = city.trim();
        }

        if (email !== undefined) {
            if (email.trim() === "") {
                // Allow removing email
                customer.email = undefined;
            } else {
                // Validate email format
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(email)) {
                    res.status(400).json({ error: "Please enter a valid email address" });
                    return;
                }

                // Check if email already exists for another user
                const existingEmail = await Customer.findOne({ 
                    email: email.toLowerCase(),
                    _id: { $ne: user.id }
                });
                
                if (existingEmail) {
                    res.status(400).json({ error: "Email already exists" });
                    return;
                }

                customer.email = email.toLowerCase().trim();
            }
        }

        if (phone !== undefined) {
            if (!phone.trim()) {
                res.status(400).json({ error: "Phone number is required" });
                return;
            }

            // Validate phone number format
            const phoneRegex = /^[0-9]{10}$/;
            if (!phoneRegex.test(phone)) {
                res.status(400).json({ error: "Please enter a valid 10-digit phone number" });
                return;
            }

            // Check if phone already exists for another user
            const existingPhone = await Customer.findOne({ 
                phone: phone.trim(),
                _id: { $ne: user.id }
            });
            
            if (existingPhone) {
                res.status(400).json({ error: "Phone number already exists" });
                return;
            }

            customer.phone = phone.trim();
        }

        await customer.save();

        // Return updated customer data (without password)
        const updatedCustomer = await Customer.findById(user.id).select('-password');
        
        res.status(200).json({
            message: "Profile updated successfully",
            customer: updatedCustomer
        });

    } catch (err: any) {
        console.error('Update profile error:', err);
        if (err.code === 11000) {
            if (err.keyPattern?.email) {
                res.status(400).json({ error: "Email already exists" });
            } else if (err.keyPattern?.phone) {
                res.status(400).json({ error: "Phone number already exists" });
            } else {
                res.status(400).json({ error: "Duplicate entry found" });
            }
        } else {
            res.status(500).json({ error: "Internal server error" });
        }
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

// Get Profile endpoint
app.get("/profile", authenticateToken, async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user; // decoded JWT already set in middleware
        const customer = await Customer.findById(user.id).select('-password');

        if (!customer) {
            res.status(404).json({ error: "Customer not found" });
            return;
        }

        res.json(customer);
    } catch (err: any) {
        console.error('Profile error:', err);
        res.status(500).json({ error: "Internal server error" });
    }
});

//##################################################################################################################
// QR Code Scanning and Points System

// Scan QR Code endpoint
app.post("/api/scan-qr", authenticateToken, async (req: Request, res: Response): Promise<void> => {
    try {
        const { qrData } = req.body;
        const user = (req as any).user;

        if (!qrData) {
            res.status(400).json({
                success: false,
                message: "QR data is required"
            });
            return;
        }

        // Parse QR data to extract qrId, batchId, and points
        let qrId: string;
        let batchId: string;
        let points: number;

        try {
            // Parse the QR data format: "QR ID: XXX\nBatch ID: XXX\nPoints: XXX\nURL: XXX"
            const lines = (qrData as string).split('\n') as string[];

            const qrIdLine = lines.find((line: string) => line.trim().startsWith('QR ID:'));
            const batchIdLine = lines.find((line: string) => line.trim().startsWith('Batch ID:'));
            const pointsLine = lines.find((line: string) => line.trim().startsWith('Points:'));

            if (!qrIdLine || !batchIdLine || !pointsLine) {
                throw new Error('Invalid QR format - missing required fields');
            }

            qrId = qrIdLine.split(':')[1].trim();
            batchId = batchIdLine.split(':')[1].trim();
            points = parseInt(pointsLine.split(':')[1].trim());

            if (isNaN(points) || points <= 0) {
                throw new Error('Invalid points value');
            }

        } catch (parseError) {
            res.status(400).json({
                success: false,
                message: "Invalid QR code format. Expected format: QR ID, Batch ID, Points, URL"
            });
            return;
        }

        // Find the QR batch using batchId
        const qrBatch = await QRBatch.findOne({
            batchId: batchId,
            isActive: true
        });

        if (!qrBatch) {
            res.status(404).json({
                success: false,
                message: "QR batch not found or inactive"
            });
            return;
        }

        // Find the specific QR code within the batch using qrId
        const qrCode = qrBatch.qrCodes.find(qr => qr.qrId === qrId);

        if (!qrCode) {
            res.status(404).json({
                success: false,
                message: "QR code not found in batch"
            });
            return;
        }

        // Check if QR code has already been scanned
        if (qrCode.isScanned) {
            res.status(400).json({
                success: false,
                message: "This QR code has already been scanned and redeemed"
            });
            return;
        }

        // Update customer points
        const customer = await Customer.findByIdAndUpdate(
            user.id,
            { $inc: { points: points } },
            { new: true }
        ).select('-password');

        if (!customer) {
            res.status(404).json({
                success: false,
                message: "Customer not found"
            });
            return;
        }

        // Mark QR code as scanned
        qrCode.isScanned = true;
        await qrBatch.save();

        res.status(200).json({
            success: true,
            message: `Successfully earned ${points} points!`,
            data: {
                pointsEarned: points,
                totalPoints: customer.points,
                qrId: qrId,
                batchId: batchId,
                customer: {
                    id: customer._id,
                    name: customer.name,
                    username: customer.username,
                    points: customer.points
                }
            }
        });

    } catch (error: any) {
        console.error('Error scanning QR code:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

//##################################################################################################################
// Replace your existing schemes endpoint in your client backend with this:

app.get('/api/schemes', async (req: Request, res: Response): Promise<void> => {
    try {
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;
        const skip = (page - 1) * limit;

        // Get total count for pagination
        const totalSchemes = await Scheme.countDocuments();

        // Get schemes with pagination
        const schemes = await Scheme.find()
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        // ADMIN_BACKEND_URL should point to your admin backend where images are stored
        const ADMIN_BACKEND_URL = process.env.ADMIN_BACKEND_URL 
        const schemesWithImageUrls = schemes.map(scheme => {
            const schemeObj = scheme.toObject();
            
            let fullImageUrl = null;
            
            // If scheme has an image field
            if (schemeObj.image) {
                // If it's already a complete URL, use as is
                if (schemeObj.image.startsWith('http')) {
                    fullImageUrl = schemeObj.image;
                } 
                // If it's a relative path, prepend admin backend URL
                else {
                    // Remove leading slash if present to avoid double slashes
                    const imagePath = schemeObj.image.startsWith('/') ? schemeObj.image : `/${schemeObj.image}`;
                    fullImageUrl = `${ADMIN_BACKEND_URL}${imagePath}`;
                }
            }
            
            return {
                ...schemeObj,
                image: fullImageUrl,
                images: fullImageUrl // Keep both for compatibility
            };
        });

        const totalPages = Math.ceil(totalSchemes / limit);

        res.status(200).json({
            success: true,
            data: schemesWithImageUrls,
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

//##################################################################################################################
// Get customer points by username
app.get('/api/customers/:username/points', async (req: Request, res: Response): Promise<void> => {
    try {
        const { username } = req.params;

        const customer = await Customer.findOne({ username }).select('username points name');

        if (!customer) {
            res.status(404).json({
                success: false,
                message: 'Customer not found'
            });
            return;
        }

        res.status(200).json({
            success: true,
            data: {
                username: customer.username,
                name: customer.name,
                points: customer.points
            }
        });

    } catch (error: any) {
        console.error('Error fetching customer points:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Update customer points (bonus endpoint for points management)
app.patch('/api/customers/:username/points', async (req: Request, res: Response): Promise<void> => {
    try {
        const { username } = req.params;
        const { points, operation = 'set' } = req.body; // operation: 'set', 'add', 'subtract'

        if (typeof points !== 'number') {
            res.status(400).json({
                success: false,
                message: 'Points must be a number'
            });
            return;
        }

        const customer = await Customer.findOne({ username });

        if (!customer) {
            res.status(404).json({
                success: false,
                message: 'Customer not found'
            });
            return;
        }

        let newPoints: number;

        switch (operation) {
            case 'add':
                newPoints = customer.points + points;
                break;
            case 'subtract':
                newPoints = Math.max(0, customer.points - points); // Don't allow negative points
                break;
            case 'set':
            default:
                newPoints = Math.max(0, points);
                break;
        }

        const updatedCustomer = await Customer.findOneAndUpdate(
            { username },
            { points: newPoints },
            { new: true }
        ).select('username name points');

        res.status(200).json({
            success: true,
            message: `Customer points ${operation === 'set' ? 'updated' : operation === 'add' ? 'added' : 'subtracted'} successfully`,
            data: {
                username: updatedCustomer?.username,
                name: updatedCustomer?.name,
                previousPoints: customer.points,
                currentPoints: updatedCustomer?.points,
                operation
            }
        });

    } catch (error: any) {
        console.error('Error updating customer points:', error);
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