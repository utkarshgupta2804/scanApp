import express, { Request, Response } from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import mongoose, { Document, Schema } from "mongoose";
import dotenv from "dotenv";
import { Scheme, IScheme } from "./models/scheme";
import Customer from "./models/customer";
import { QR } from "./models/qrs";
import multer from "multer";
import path from 'path';
import fs from 'fs';

// Configure multer for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/schemes/';
        // Create directory if it doesn't exist
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        // Generate unique filename with timestamp
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `scheme-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});

// File filter to accept only images
const fileFilter = (req: any, file: any, cb: any) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 20 * 1024 * 1024, // 20MB limit
        files: 1 
    }
});

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
    cors({
        credentials: true,
        origin: [
            process.env.CLIENT_URL || "http://localhost:3000",
        ],
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    })
);

// Constants
const salt = bcrypt.genSaltSync(10);
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

//##################################################################################################################
// API 1: Register a new scheme (updated for single image)
app.post('/api/schemes', upload.single('image'), async (req: Request, res: Response): Promise<void> => {
    try {
        const {
            title,
            description,
            pointsRequired
        } = req.body;

        // Check if scheme with same title already exists
        const existingScheme = await Scheme.findOne({
            title: { $regex: new RegExp(`^${title}$`, 'i') }
        });

        if (existingScheme) {
            // Clean up uploaded file if scheme already exists
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            
            res.status(400).json({
                success: false,
                message: 'Scheme with this title already exists'
            });
            return;
        }

        // Process uploaded image
        let imagePath: string = '';
        if (req.file) {
            imagePath = req.file.path.replace(/\\/g, '/');
        }

        // Create new scheme
        const newScheme = new Scheme({
            title,
            description,
            image: imagePath, // Single image field instead of array
            pointsRequired: parseInt(pointsRequired)
        });

        const savedScheme = await newScheme.save();

        res.status(201).json({
            success: true,
            message: 'Scheme created successfully',
            data: savedScheme
        });

    } catch (error: any) {
        console.error('Error creating scheme:', error);

        // Clean up uploaded file on error
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }

        // Handle multer errors
        if (error instanceof multer.MulterError) {
            let message = 'File upload error';
            if (error.code === 'LIMIT_FILE_SIZE') {
                message = 'File size too large. Maximum 20MB allowed.';
            } else if (error.code === 'LIMIT_UNEXPECTED_FILE') {
                message = 'Unexpected file field. Only "image" field is allowed.';
            }
            
            res.status(400).json({
                success: false,
                message,
                error: error.message
            });
            return;
        }

        // Handle validation errors
        if (error.name === 'ValidationError') {
            const validationErrors = Object.values(error.errors).map((err: any) => err.message);
            res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: validationErrors
            });
            return;
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// GET - Fetch all schemes (no changes needed)
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

        res.status(200).json({
            success: true,
            data: schemes,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(totalSchemes / limit),
                totalSchemes,
                hasNextPage: page < Math.ceil(totalSchemes / limit),
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

// PUT - Update scheme with optional new image upload (updated for single image)
app.put('/api/schemes/:id', upload.single('image'), async (req: Request, res: Response): Promise<void> => {
    try {
        const { id } = req.params;
        const {
            title,
            description,
            pointsRequired,
            removeExistingImage // Boolean flag to remove existing image
        } = req.body;

        // Validate ObjectId format
        if (!mongoose.Types.ObjectId.isValid(id)) {
            // Clean up uploaded file
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            
            res.status(400).json({
                success: false,
                message: 'Invalid scheme ID format'
            });
            return;
        }

        // Check if scheme exists
        const existingScheme = await Scheme.findById(id);
        if (!existingScheme) {
            // Clean up uploaded file
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            
            res.status(404).json({
                success: false,
                message: 'Scheme not found'
            });
            return;
        }

        // If title is being updated, check for duplicates (excluding current scheme)
        if (title && title !== existingScheme.title) {
            const duplicateScheme = await Scheme.findOne({
                title: { $regex: new RegExp(`^${title}$`, 'i') },
                _id: { $ne: id }
            });

            if (duplicateScheme) {
                // Clean up uploaded file
                if (req.file && fs.existsSync(req.file.path)) {
                    fs.unlinkSync(req.file.path);
                }
                
                res.status(400).json({
                    success: false,
                    message: 'Scheme with this title already exists'
                });
                return;
            }
        }

        // Handle image update
        let updatedImage = existingScheme.image;

        // Remove existing image if requested
        if (removeExistingImage === 'true' || removeExistingImage === true) {
            // Remove existing image from file system
            if (existingScheme.image && fs.existsSync(existingScheme.image)) {
                fs.unlinkSync(existingScheme.image);
            }
            updatedImage = '';
        }

        // Add new uploaded image
        if (req.file) {
            const newImagePath = req.file.path.replace(/\\/g, '/');
            
            // If there's a new image, remove the old one first (replace scenario)
            if (existingScheme.image && !removeExistingImage && fs.existsSync(existingScheme.image)) {
                fs.unlinkSync(existingScheme.image);
            }
            
            updatedImage = newImagePath;
        }

        // Prepare update object with only provided fields
        const updateData: Partial<IScheme> = {};

        if (title !== undefined) updateData.title = title;
        if (description !== undefined) updateData.description = description;
        if (pointsRequired !== undefined) updateData.pointsRequired = parseInt(pointsRequired);
        
        // Update image only if there's a change
        if (req.file || removeExistingImage) {
            updateData.image = updatedImage;
        }

        // Update the scheme
        const updatedScheme = await Scheme.findByIdAndUpdate(
            id,
            updateData,
            {
                new: true, // Return updated document
                runValidators: true // Run schema validators
            }
        );

        res.status(200).json({
            success: true,
            message: 'Scheme updated successfully',
            data: updatedScheme
        });

    } catch (error: any) {
        console.error('Error updating scheme:', error);

        // Clean up uploaded file on error
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }

        // Handle multer errors
        if (error instanceof multer.MulterError) {
            let message = 'File upload error';
            if (error.code === 'LIMIT_FILE_SIZE') {
                message = 'File size too large. Maximum 20MB allowed.';
            } else if (error.code === 'LIMIT_UNEXPECTED_FILE') {
                message = 'Unexpected file field. Only "image" field is allowed.';
            }
            
            res.status(400).json({
                success: false,
                message,
                error: error.message
            });
            return;
        }

        // Handle validation errors
        if (error.name === 'ValidationError') {
            const validationErrors = Object.values(error.errors).map((err: any) => err.message);
            res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: validationErrors
            });
            return;
        }

        // Handle cast errors (invalid ObjectId)
        if (error.name === 'CastError') {
            res.status(400).json({
                success: false,
                message: 'Invalid scheme ID'
            });
            return;
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});


//##################################################################################################################
// Get all customers with pagination
app.get('/api/customers', async (req: Request, res: Response): Promise<void> => {
    try {
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;
        const sortBy = (req.query.sortBy as string) || 'createdAt';
        const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
        const skip = (page - 1) * limit;

        // Build sort object
        const sort: any = {};
        sort[sortBy] = sortOrder;

        // Get total count for pagination
        const totalCustomers = await Customer.countDocuments();

        // Get customers with pagination and sorting, exclude password field
        const customers = await Customer.find()
            .sort(sort)
            .skip(skip)
            .limit(limit)
            .select('-password -__v'); // Exclude password and version field

        const totalPages = Math.ceil(totalCustomers / limit);

        res.status(200).json({
            success: true,
            data: customers,
            pagination: {
                currentPage: page,
                totalPages,
                totalCustomers,
                hasNextPage: page < totalPages,
                hasPrevPage: page > 1
            }
        });

    } catch (error: any) {
        console.error('Error fetching customers:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Filter customers based on different criteria
app.get('/api/customers/filter', async (req: Request, res: Response): Promise<void> => {
    try {
        const {
            city,
            minPoints,
            maxPoints,
            search,
            sortBy,
            sortOrder,
            page,
            limit
        } = req.query;

        // Build filter object
        const filter: any = {};

        // City filter
        if (city) {
            filter.city = { $regex: city, $options: 'i' };
        }

        // Points range filter
        if (minPoints || maxPoints) {
            filter.points = {};
            if (minPoints) filter.points.$gte = parseInt(minPoints as string);
            if (maxPoints) filter.points.$lte = parseInt(maxPoints as string);
        }

        // Search filter (searches in name and username)
        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { username: { $regex: search, $options: 'i' } }
            ];
        }

        // Pagination
        const pageNum = parseInt(page as string) || 1;
        const limitNum = parseInt(limit as string) || 10;
        const skip = (pageNum - 1) * limitNum;

        // Sorting
        const sort: any = {};
        const sortField = (sortBy as string) || 'createdAt';
        const sortDirection = sortOrder === 'asc' ? 1 : -1;
        sort[sortField] = sortDirection;

        // Get total count for pagination
        const totalCustomers = await Customer.countDocuments(filter);

        // Get filtered customers
        const customers = await Customer.find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limitNum)
            .select('-password -__v');

        const totalPages = Math.ceil(totalCustomers / limitNum);

        // Get unique cities for filter options
        const cities = await Customer.distinct('city');

        res.status(200).json({
            success: true,
            data: customers,
            filters: {
                appliedFilters: {
                    city,
                    minPoints,
                    maxPoints,
                    search
                },
                availableFilters: {
                    cities
                }
            },
            pagination: {
                currentPage: pageNum,
                totalPages,
                totalCustomers,
                hasNextPage: pageNum < totalPages,
                hasPrevPage: pageNum > 1
            }
        });

    } catch (error: any) {
        console.error('Error filtering customers:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Add this endpoint to your Node.js backend
app.patch('/api/customers/:id/points', async (req: Request, res: Response): Promise<void> => {
    try {
        const { id } = req.params;
        const { points } = req.body;

        // Validate points
        if (typeof points !== 'number' || points < 0) {
            res.status(400).json({
                success: false,
                message: 'Points must be a non-negative number'
            });
            return;
        }

        // Update customer points
        const updatedCustomer = await Customer.findByIdAndUpdate(
            id,
            {
                points: points,
                updatedAt: new Date()
            },
            {
                new: true, // Return the updated document
                select: '-password -__v' // Exclude password and version field
            }
        );

        if (!updatedCustomer) {
            res.status(404).json({
                success: false,
                message: 'Customer not found'
            });
            return;
        }

        res.status(200).json({
            success: true,
            message: 'Customer points updated successfully',
            data: updatedCustomer
        });

    } catch (error: any) {
        console.error('Error updating customer points:', error);

        // Handle invalid ObjectId format
        if (error.name === 'CastError') {
            res.status(400).json({
                success: false,
                message: 'Invalid customer ID format'
            });
            return;
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

//##################################################################################################################
app.post('/api/generate-qr', async (req: Request, res: Response): Promise<void> => {
    try {
        const {
            points,
            url,
            format = 'png',
            size = '200x200'
        } = req.body;

        // Validation
        if (!points) {
            res.status(400).json({
                success: false,
                message: 'Points parameter is required'
            });
            return;
        }

        if (!url) {
            res.status(400).json({
                success: false,
                message: 'URL parameter is required'
            });
            return;
        }

        // Validate format
        const validFormats = ['png', 'jpg', 'jpeg', 'svg'];
        if (!validFormats.includes(format.toLowerCase())) {
            res.status(400).json({
                success: false,
                message: 'Invalid format. Supported formats: png, jpg, jpeg, svg'
            });
            return;
        }

        // Validate size format (should be WIDTHxHEIGHT)
        const sizePattern = /^\d+x\d+$/;
        if (!sizePattern.test(size)) {
            res.status(400).json({
                success: false,
                message: 'Invalid size format. Use format: WIDTHxHEIGHT (e.g., 200x200)'
            });
            return;
        }

        // Extract width and height for validation
        const [width, height] = size.split('x').map(Number);

        // Validate size limits based on format
        const maxSize = ['svg'].includes(format.toLowerCase()) ? 1000000 : 1000;
        if (width < 10 || height < 10 || width > maxSize || height > maxSize) {
            res.status(400).json({
                success: false,
                message: `Size must be between 10x10 and ${maxSize}x${maxSize} for ${format} format`
            });
            return;
        }

        // Validate square dimensions
        if (width !== height) {
            res.status(400).json({
                success: false,
                message: 'QR code must be square (width must equal height)'
            });
            return;
        }

        // Validate URL format
        try {
            new URL(url);
        } catch (error) {
            res.status(400).json({
                success: false,
                message: 'Invalid URL format'
            });
            return;
        }

        // Create QR data with points and URL
        const qrData = `Points: ${points}\nURL: ${url}`;

        // Encode the data for URL
        const encodedData = encodeURIComponent(qrData);

        // Build goQR API URL with standard black and white colors
        const goQRUrl = `https://api.qrserver.com/v1/create-qr-code/` +
            `?data=${encodedData}` +
            `&size=${size}` +
            `&format=${format.toLowerCase()}` +
            `&color=0-0-0` +        // Black QR code
            `&bgcolor=255-255-255` + // White background
            `&ecc=L` +              // Low error correction for better compatibility
            `&margin=1` +           // 1 pixel margin
            `&qzone=4`;             // 4 module quiet zone (recommended)

        // Function to generate custom QR id
        function generateQRId(): string {
            const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
            let randomPart = '';
            for (let i = 0; i < 5; i++) {  // 5 chars = shorter, total length ~7 with "QR"
                randomPart += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return `QR${randomPart}`;
        }

        // Save QR code to database with custom id
        const newQR = await QR.create({
            qrId: generateQRId(),
            points,
            url,
            format: format.toLowerCase(),
            size,
            qrCodeUrl: goQRUrl,  // <-- saved
            qrData: qrData,      // <-- saved
            createdAt: new Date()
        });

        res.status(200).json({
            success: true,
            message: 'QR code generated and saved successfully',
            data: {
                qrId: newQR.qrId,  // use custom id
                points: points,
                url: url,
                format: format.toLowerCase(),
                size: size,
                qrCodeUrl: goQRUrl,
                qrData: qrData,
                createdAt: newQR.createdAt
            }
        });


    } catch (error: any) {
        console.error('Error generating QR code:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Get all QR codes with pagination, sorting, and filtering
app.get('/api/qrs', async (req: Request, res: Response): Promise<void> => {
    try {
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;
        const sortBy = (req.query.sortBy as string) || 'createdAt';
        const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
        const skip = (page - 1) * limit;

        // Build sort object
        const sort: any = {};
        sort[sortBy] = sortOrder;

        // Get total count for pagination
        const totalQRs = await QR.countDocuments();

        // Get QR codes with pagination and sorting
        const qrs = await QR.find()
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .select('qrId points url format size qrCodeUrl qrData createdAt updatedAt isActive');
    

        const totalPages = Math.ceil(totalQRs / limit);

        res.status(200).json({
            success: true,
            data: qrs,
            pagination: {
                currentPage: page,
                totalPages,
                totalQRs,
                hasNextPage: page < totalPages,
                hasPrevPage: page > 1
            }
        });

    } catch (error: any) {
        console.error('Error fetching QR codes:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Get single QR code by qrId
app.get('/api/qrs/:qrId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { qrId } = req.params;

        const qr = await QR.findOne({ qrId });

        if (!qr) {
            res.status(404).json({
                success: false,
                message: 'QR code not found'
            });
            return;
        }

        res.status(200).json({
            success: true,
            data: qr
        });

    } catch (error: any) {
        console.error('Error fetching QR code:', error);
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

app.use('/uploads', express.static('uploads'));
const PORT = process.env.PORT || 4000;

const startServer = async (): Promise<void> => {
    try {
        await connectDB();

        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
            console.log(`📡 API endpoints available at http://localhost:${PORT}/api/`);
            console.log('🔗 Available endpoints:');
            console.log(`   GET  http://localhost:${PORT}/api/test`);
            console.log(`   GET  http://localhost:${PORT}/api/schemes`);
            console.log(`   POST http://localhost:${PORT}/api/schemes`);
            console.log(`   GET  http://localhost:${PORT}/api/schemes/:id`);
        });
    } catch (error) {
        console.error("❌ Failed to start server:", error);
        process.exit(1);
    }
};

startServer().catch((error) => {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
});