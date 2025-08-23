import express, { Request, Response } from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import mongoose, { Document, Schema } from "mongoose";
import dotenv from "dotenv";
import { Scheme, IScheme } from "./models/scheme";
import Customer from "./models/customer";
import { QRBatch,IQRItem } from "./models/qrs";
import multer from "multer";
import path from 'path';
import fs from 'fs';

// Configure multer for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/';
        // Create directory if it doesn't exist
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        let schemeTitle = req.body.title || "default";
        schemeTitle = schemeTitle.replace(/[^a-z0-9\-]/gi, '').toLowerCase();
        const ext = path.extname(file.originalname);
        cb(null, `scheme-${schemeTitle}-${Date.now()}${ext}`);
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
app.use('/uploads', express.static(path.resolve('uploads')));
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
        let imagePath = '';
        if (req.file) {
            imagePath = `/uploads/${req.file.filename}`;
        }
        const newScheme = new Scheme({
            title,
            description,
            image: imagePath,
            pointsRequired: parseInt(pointsRequired),
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
            const newImagePath = `/uploads/${req.file.filename}`;

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
function generateBatchId(): string {
    const timestamp = Date.now().toString(36);
    const randomPart = Math.random().toString(36).substring(2, 8);
    return `BATCH_${timestamp}_${randomPart}`.toUpperCase();
}

// Generate QR ID
function generateQRId(): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let randomPart = '';
    for (let i = 0; i < 5; i++) {
        randomPart += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `QR${randomPart}`;
}

// Generate QR codes (both single and bulk)
app.post('/api/generate-qr', async (req: Request, res: Response): Promise<void> => { 
    try {
        const {
            points,
            url,
            format = 'png',
            size = '200x200',
            quantity = 1
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

        const qty = parseInt(quantity);
        if (!qty || qty < 1 || qty > 100) {
            res.status(400).json({
                success: false,
                message: 'Quantity must be between 1 and 100'
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

        // Validate size format
        const sizePattern = /^\d+x\d+$/;
        if (!sizePattern.test(size)) {
            res.status(400).json({
                success: false,
                message: 'Invalid size format. Use format: WIDTHxHEIGHT (e.g., 200x200)'
            });
            return;
        }

        const [width, height] = size.split('x').map(Number);
        const maxSize = ['svg'].includes(format.toLowerCase()) ? 1000000 : 1000;
        
        if (width < 10 || height < 10 || width > maxSize || height > maxSize) {
            res.status(400).json({
                success: false,
                message: `Size must be between 10x10 and ${maxSize}x${maxSize} for ${format} format`
            });
            return;
        }

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

        // Generate QR codes
        const qrCodes: IQRItem[] = [];
        const errors: any[] = [];

        for (let i = 0; i < qty; i++) {
            try {
                const qrId = generateQRId();
                
                // Create QR data with QR ID included
                const qrData = `QR ID: ${qrId}\nPoints: ${points}\nURL: ${url}`;
                const encodedData = encodeURIComponent(qrData);

                const goQRUrl = `https://api.qrserver.com/v1/create-qr-code/` +
                    `?data=${encodedData}` +
                    `&size=${size}` +
                    `&format=${format.toLowerCase()}` +
                    `&color=0-0-0` +
                    `&bgcolor=255-255-255` +
                    `&ecc=L` +
                    `&margin=1` +
                    `&qzone=4`;

                qrCodes.push({
                    qrId,
                    qrCodeUrl: goQRUrl
                });

                // Small delay to prevent overwhelming external API
                if (i < qty - 1) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

            } catch (error: any) {
                errors.push({
                    index: i + 1,
                    error: error.message
                });
            }
        }

        if (qrCodes.length === 0) {
            res.status(500).json({
                success: false,
                message: 'Failed to generate any QR codes',
                errors
            });
            return;
        }

        // Save batch to database - store original format for display
        const batchId = generateBatchId();
        const batchQRData = `Points: ${points}\nURL: ${url}`;
        
        const newBatch = await QRBatch.create({
            batchId,
            qrData: batchQRData, // Keep original format for batch display
            format: format.toLowerCase(),
            size,
            qrCodes,
            totalCount: qrCodes.length,
            isActive: true
        });

        res.status(200).json({
            success: true,
            message: `Successfully generated ${qrCodes.length} QR code(s)${errors.length > 0 ? ` with ${errors.length} errors` : ''}`,
            data: {
                batchId: newBatch.batchId,
                qrData: newBatch.qrData,
                format: newBatch.format,
                size: newBatch.size,
                qrCodes: newBatch.qrCodes,
                totalCount: newBatch.totalCount,
                createdAt: newBatch.createdAt,
                errors: errors.length > 0 ? errors : undefined
            }
        });

    } catch (error: any) {
        console.error('Error generating QR codes:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Get all QR batches with pagination
app.get('/api/qr-batches', async (req: Request, res: Response): Promise<void> => {
    try {
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;
        const sortBy = (req.query.sortBy as string) || 'createdAt';
        const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
        const skip = (page - 1) * limit;

        const sort: any = {};
        sort[sortBy] = sortOrder;

        const totalBatches = await QRBatch.countDocuments({ isActive: true });
        
        const batches = await QRBatch.find({ isActive: true })
            .sort(sort)
            .skip(skip)
            .limit(limit)
            .select('batchId qrData format size qrCodes totalCount createdAt updatedAt isActive');

        const totalPages = Math.ceil(totalBatches / limit);

        res.status(200).json({
            success: true,
            data: batches,
            pagination: {
                currentPage: page,
                totalPages,
                totalBatches,
                hasNextPage: page < totalPages,
                hasPrevPage: page > 1
            }
        });

    } catch (error: any) {
        console.error('Error fetching QR batches:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Get single QR batch by batchId
app.get('/api/qr-batches/:batchId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { batchId } = req.params;

        const batch = await QRBatch.findOne({ batchId, isActive: true });

        if (!batch) {
            res.status(404).json({
                success: false,
                message: 'QR batch not found'
            });
            return;
        }

        res.status(200).json({
            success: true,
            data: batch
        });

    } catch (error: any) {
        console.error('Error fetching QR batch:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Delete QR batch
app.delete('/api/qr-batches/:batchId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { batchId } = req.params;

        const batch = await QRBatch.findOneAndUpdate(
            { batchId },
            { isActive: false },
            { new: true }
        );

        if (!batch) {
            res.status(404).json({
                success: false,
                message: 'QR batch not found'
            });
            return;
        }

        res.status(200).json({
            success: true,
            message: 'QR batch deleted successfully'
        });

    } catch (error: any) {
        console.error('Error deleting QR batch:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Job status tracking for async operations
interface JobStatus {
    id: string;
    status: 'pending' | 'processing' | 'completed' | 'failed';
    progress: number;
    total: number;
    result?: any;
    error?: string;
    createdAt: Date;
}

const jobStorage = new Map<string, JobStatus>();

function generateJobId(): string {
    return `job_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
}

// Async bulk generation (for very large quantities)
app.post('/api/generate-bulk-qr-async', async (req: Request, res: Response): Promise<void> => {
    try {
        const {
            points,
            url,
            format = 'png',
            size = '200x200',
            quantity = 1
        } = req.body;

        // Basic validation
        if (!points || !url || !quantity || quantity < 1 || quantity > 100) {
            res.status(400).json({
                success: false,
                message: 'Invalid parameters'
            });
            return;
        }

        const jobId = generateJobId();
        
        jobStorage.set(jobId, {
            id: jobId,
            status: 'pending',
            progress: 0,
            total: quantity,
            createdAt: new Date()
        });

        processQRGeneration(jobId, { points, url, format, size, quantity });

        res.status(202).json({
            success: true,
            message: 'QR generation job started',
            jobId: jobId
        });

    } catch (error: any) {
        console.error('Error starting bulk QR generation:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Job status endpoint
app.get('/api/job-status/:jobId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { jobId } = req.params;
        const job = jobStorage.get(jobId);

        if (!job) {
            res.status(404).json({
                success: false,
                message: 'Job not found'
            });
            return;
        }

        res.status(200).json({
            success: true,
            data: job
        });

    } catch (error: any) {
        console.error('Error fetching job status:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// Process QR generation asynchronously
async function processQRGeneration(jobId: string, params: any) {
    const job = jobStorage.get(jobId);
    if (!job) return;

    try {
        job.status = 'processing';
        jobStorage.set(jobId, job);

        const { points, url, format, size, quantity } = params;
        const qrCodes: IQRItem[] = [];
        const errors: any[] = [];

        for (let i = 0; i < quantity; i++) {
            try {
                const qrId = generateQRId();
                
                // Create QR data with QR ID included for each individual QR code
                const qrData = `QR ID: ${qrId}\nPoints: ${points}\nURL: ${url}`;
                const encodedData = encodeURIComponent(qrData);
                
                const goQRUrl = `https://api.qrserver.com/v1/create-qr-code/` +
                    `?data=${encodedData}&size=${size}&format=${format.toLowerCase()}` +
                    `&color=0-0-0&bgcolor=255-255-255&ecc=L&margin=1&qzone=4`;

                qrCodes.push({
                    qrId,
                    qrCodeUrl: goQRUrl
                });

                job.progress = i + 1;
                jobStorage.set(jobId, job);

                if (i < quantity - 1) {
                    await new Promise(resolve => setTimeout(resolve, 200));
                }

            } catch (error: any) {
                errors.push({
                    index: i + 1,
                    error: error.message
                });
            }
        }

        // Save batch to database
        const batchId = generateBatchId();
        const batchQRData = `Points: ${points}\nURL: ${url}`;
        
        const newBatch = await QRBatch.create({
            batchId,
            qrData: batchQRData, // Keep original format for batch display
            format: format.toLowerCase(),
            size,
            qrCodes,
            totalCount: qrCodes.length,
            isActive: true
        });

        job.status = 'completed';
        job.result = {
            batchId: newBatch.batchId,
            qrData: newBatch.qrData,
            qrCodes: newBatch.qrCodes,
            totalCount: newBatch.totalCount,
            errors,
            summary: {
                requested: quantity,
                successful: qrCodes.length,
                failed: errors.length
            }
        };
        jobStorage.set(jobId, job);

        // Clean up job after 1 hour
        setTimeout(() => {
            jobStorage.delete(jobId);
        }, 60 * 60 * 1000);

    } catch (error: any) {
        job.status = 'failed';
        job.error = error.message;
        jobStorage.set(jobId, job);
    }
}

// Add new endpoint to get QR data by QR ID
app.get('/api/qr/:qrId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { qrId } = req.params;

        // Find the batch containing this QR ID
        const batch = await QRBatch.findOne({
            'qrCodes.qrId': qrId,
            isActive: true
        });

        if (!batch) {
            res.status(404).json({
                success: false,
                message: 'QR code not found'
            });
            return;
        }

        // Find the specific QR code
        const qrCode = batch.qrCodes.find(qr => qr.qrId === qrId);
        
        if (!qrCode) {
            res.status(404).json({
                success: false,
                message: 'QR code not found in batch'
            });
            return;
        }

        // Parse batch data to get points and URL
        const lines = batch.qrData.split('\n');
        const points = lines[0]?.replace('Points: ', '') || '';
        const url = lines[1]?.replace('URL: ', '') || '';

        res.status(200).json({
            success: true,
            data: {
                qrId: qrCode.qrId,
                points: parseInt(points) || 0,
                url: url,
                qrCodeUrl: qrCode.qrCodeUrl,
                batchId: batch.batchId,
                createdAt: batch.createdAt
            }
        });

    } catch (error: any) {
        console.error('Error fetching QR data:', error);
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

const PORT = process.env.PORT || 4000;

const startServer = async (): Promise<void> => {
    try {
        await connectDB();
        app.listen(PORT, () => {
            console.log(`http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
};

startServer().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
})