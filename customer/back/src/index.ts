import express, { Request, Response } from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import mongoose, { Document, Schema } from "mongoose";
import dotenv from "dotenv";
import crypto from "crypto";
import nodemailer from "nodemailer";
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
        origin: process.env.CLIENT_URL ,
    })
);

// Constants
const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET || "";

// Enhanced Email transporter configuration with better error handling
const createEmailTransporter = () => {
    console.log('Creating email transporter with config:', {
        host: process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.EMAIL_PORT || '587'),
        user: process.env.EMAIL_USER ? '***configured***' : 'NOT_SET',
        pass: process.env.EMAIL_PASSWORD ? '***configured***' : 'NOT_SET'
    });

    return nodemailer.createTransport({
        host: process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.EMAIL_PORT || '587'),
        secure: process.env.EMAIL_PORT === '465', // true for 465, false for other ports
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
        // Add these additional options for better reliability
        tls: {
            rejectUnauthorized: false // Allow self-signed certificates
        },
        debug: process.env.NODE_ENV !== 'production', // Enable debug in development
        logger: process.env.NODE_ENV !== 'production' // Enable logging in development
    });
};

// Test email configuration on startup
const testEmailConfiguration = async () => {
    try {
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            console.warn('⚠️  EMAIL_USER or EMAIL_PASSWORD not configured. Email functionality will be disabled.');
            return false;
        }

        const transporter = createEmailTransporter();

        // Verify the connection configuration
        await transporter.verify();
        console.log('✅ Email server connection verified successfully');
        return true;
    } catch (error) {
        console.error('❌ Email server verification failed:', error);
        return false;
    }
};

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

// Middleware to authenticate JWT token
const authenticateToken = (req: Request, res: Response, next: any) => {
    let token;
    
    // Check Authorization header first
    if (req.headers.authorization) {
        // Clean up the authorization header - remove extra spaces and line breaks
        const authHeader = req.headers.authorization.replace(/\s+/g, ' ').trim();
        if (authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7).trim(); // Remove "Bearer " and trim any remaining spaces
        }
    }
    // Fallback to cookies
    else if (req.cookies && req.cookies.token) {
        token = req.cookies.token.trim(); // Also trim cookie token just in case
    }

    if (!token) {
        res.status(401).json({ error: "Access token required" });
        return;
    }

    try {
        const decoded = jwt.verify(token, secret) as JWTPayload;
        (req as any).user = decoded;
        next();
    } catch (err) {
        console.log('Token verification error:', err);
        console.log('Token received:', token);
        res.status(403).json({ error: "Invalid or expired token" });
    }
};

//##################################################################################################################
// Register endpoint - Updated to include email
app.post("/register", async (req: Request, res: Response): Promise<void> => {
    const { name, city, username, email, password }: {
        name: string;
        city: string;
        username: string;
        email: string;
        password: string;
    } = req.body;

    try {
        // Validate required fields
        if (!name || !city || !username || !email || !password) {
            res.status(400).json({ error: "All fields are required" });
            return;
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            res.status(400).json({ error: "Please enter a valid email address" });
            return;
        }

        // Check if email already exists
        const existingEmail = await Customer.findOne({ email });
        if (existingEmail) {
            res.status(400).json({ error: "Email already exists" });
            return;
        }

        // Check if username already exists
        const existingUsername = await Customer.findOne({ username });
        if (existingUsername) {
            res.status(400).json({ error: "Username already exists" });
            return;
        }

        const customerDoc = await Customer.create({
            name,
            city,
            username,
            email,
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
            } else {
                res.status(400).json({ error: "Duplicate entry found" });
            }
        } else {
            res.status(400).json({ error: err.message || "Registration failed" });
        }
    }
});

// Login endpoint - Can now use email or username
app.post("/login", async (req: Request, res: Response): Promise<void> => {
    try {
        const { identifier, password }: { identifier: string; password: string } = req.body;

        if (!identifier || !password) {
            res.status(400).json({ error: "Email/username and password are required" });
            return;
        }

        // Check if identifier is email or username
        const isEmail = identifier.includes('@');
        const query = isEmail ? { email: identifier.toLowerCase() } : { username: identifier.toLowerCase() };

        const customerDoc = await Customer.findOne(query);

        if (!customerDoc) {
            res.status(400).json({ error: "User not found" });
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

// Enhanced Forgot Password endpoint with better error handling
app.post("/forgot-password", async (req: Request, res: Response): Promise<void> => {
    try {
        const { email }: { email: string } = req.body;

        if (!email) {
            res.status(400).json({ error: "Email is required" });
            return;
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            res.status(400).json({ error: "Please enter a valid email address" });
            return;
        }

        // Check if email configuration is available
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            console.error('Email configuration missing: EMAIL_USER or EMAIL_PASSWORD not set');
            res.status(500).json({
                error: "Email service is not configured. Please contact support."
            });
            return;
        }

        const customer = await Customer.findOne({ email: email.toLowerCase() });

        if (!customer) {
            // Don't reveal if email exists or not for security
            res.status(200).json({
                message: "If an account with that email exists, we've sent a password reset link."
            });
            return;
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

        // Set token and expiry (1 hour)
        customer.resetPasswordToken = resetTokenHash;
        customer.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        await customer.save();

        // Create reset URL
        const resetURL = `${process.env.CLIENT_URL || 'http://localhost:3000'}/reset-password/${resetToken}`;

        // Email content with better styling
        const emailContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset - OilPro</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #FF6F00; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
                    .content { background-color: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #FF6F00; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 20px 0; }
                    .footer { text-align: center; margin-top: 20px; color: #666; font-size: 14px; }
                    .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 10px; border-radius: 4px; margin: 15px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🛢️ OilPro</h1>
                        <h2>Password Reset Request</h2>
                    </div>
                    <div class="content">
                        <p>Hello <strong>${customer.name}</strong>,</p>
                        
                        <p>We received a request to reset the password for your OilPro account associated with this email address.</p>
                        
                        <p>To reset your password, click the button below:</p>
                        
                        <div style="text-align: center;">
                            <a href="${resetURL}" class="button">Reset My Password</a>
                        </div>
                        <div class="warning">
                            <strong>⚠️ Important:</strong> This link will expire in 1 hour for security reasons.
                        </div>
                        
                        <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>
                        
                        <p>For security reasons, this email was sent to ${email}.</p>
                    </div>
                    <div class="footer">
                        <p>Best regards,<br><strong>The OilPro Team</strong></p>
                        <p><small>This is an automated email. Please do not reply to this message.</small></p>
                    </div>
                </div>
            </body>
            </html>
        `;

        try {
            console.log(`Attempting to send password reset email to: ${email}`);

            const transporter = createEmailTransporter();

            const mailOptions = {
                from: `"OilPro Support" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: '🔐 Password Reset Request - OilPro',
                html: emailContent,
                // Add text version as fallback
                text: `
Hello ${customer.name},

We received a request to reset your password for your OilPro account.

Click this link to reset your password: ${resetURL}

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
The OilPro Team
                `.trim()
            };

            const info = await transporter.sendMail(mailOptions);

            console.log('✅ Password reset email sent successfully:', {
                messageId: info.messageId,
                to: email,
                response: info.response
            });

            res.status(200).json({
                success: true,
                message: "If an account with that email exists, we've sent a password reset link."
            });

        } catch (emailError: any) {
            console.error('❌ Email sending failed:', {
                error: emailError.message,
                code: emailError.code,
                command: emailError.command,
                response: emailError.response,
                responseCode: emailError.responseCode
            });

            // Clear the reset token if email fails
            customer.resetPasswordToken = undefined;
            customer.resetPasswordExpires = undefined;
            await customer.save();

            // Provide more specific error messages based on the error type
            let errorMessage = "Failed to send reset email. Please try again later.";

            if (emailError.code === 'EAUTH') {
                errorMessage = "Email authentication failed. Please contact support.";
            } else if (emailError.code === 'ECONNECTION') {
                errorMessage = "Email server connection failed. Please try again later.";
            } else if (emailError.responseCode === 550) {
                errorMessage = "Invalid email address. Please check and try again.";
            }

            res.status(500).json({
                error: errorMessage,
                details: process.env.NODE_ENV === 'development' ? emailError.message : undefined
            });
        }

    } catch (err: any) {
        console.error('Forgot password endpoint error:', err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Reset Password endpoint
app.post("/reset-password/:token", async (req: Request, res: Response): Promise<void> => {
    try {
        const { token } = req.params;
        const { password }: { password: string } = req.body;

        if (!password) {
            res.status(400).json({ error: "Password is required" });
            return;
        }

        if (password.length < 6) {
            res.status(400).json({ error: "Password must be at least 6 characters long" });
            return;
        }

        // Hash the token to compare with stored hash
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        const customer = await Customer.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: new Date() }
        });

        if (!customer) {
            res.status(400).json({ error: "Invalid or expired reset token" });
            return;
        }

        // Update password
        customer.password = bcrypt.hashSync(password, salt);
        customer.resetPasswordToken = undefined;
        customer.resetPasswordExpires = undefined;
        await customer.save();

        res.status(200).json({
            message: "Password reset successful. You can now login with your new password."
        });

    } catch (err: any) {
        console.error('Reset password error:', err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Change Password endpoint (for logged-in users)
app.post("/change-password", authenticateToken, async (req: Request, res: Response): Promise<void> => {
    try {
        const { currentPassword, newPassword }: {
            currentPassword: string;
            newPassword: string;
        } = req.body;
        const user = (req as any).user;

        if (!currentPassword || !newPassword) {
            res.status(400).json({ error: "Current password and new password are required" });
            return;
        }

        if (newPassword.length < 6) {
            res.status(400).json({ error: "New password must be at least 6 characters long" });
            return;
        }

        const customer = await Customer.findById(user.id);

        if (!customer) {
            res.status(404).json({ error: "Customer not found" });
            return;
        }

        // Verify current password
        const isCurrentPasswordValid = bcrypt.compareSync(currentPassword, customer.password);

        if (!isCurrentPasswordValid) {
            res.status(400).json({ error: "Current password is incorrect" });
            return;
        }

        // Update password
        customer.password = bcrypt.hashSync(newPassword, salt);
        await customer.save();

        res.status(200).json({
            message: "Password changed successfully"
        });

    } catch (err: any) {
        console.error('Change password error:', err);
        res.status(500).json({ error: "Internal server error" });
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
app.get("/profile", authenticateToken, async (req: Request, res: Response): Promise<void> => {
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

    // Test email configuration on startup
    await testEmailConfiguration();

    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
};

startServer().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
});