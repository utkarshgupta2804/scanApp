import express, { Request, Response } from 'express';
import axios from 'axios';
import { QR, IQR }  from './models/qrs';
import Customer, { ICustomer} from './models/customer';
import FormData from 'form-data';
import mongoose from 'mongoose';
import multer from 'multer';

const router = express.Router();

// Configure multer for file upload
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 1048576 // 1MB limit as per goqr API
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only PNG, JPEG, JPG, and GIF are allowed.'));
        }
    }
});

// Interface for API responses
interface QRScanResponse {
    success: boolean;
    message: string;
    data?: {
        qrId: string;
        pointsEarned: number;
        customerTotalPoints: number;
        customerName: string;
    };
    error?: string;
}

// Interface for goqr API response
interface GoQRAPIResponse {
    type: string;
    symbol: Array<{
        seq: number;
        data: string | null;
        error: string | null;
    }>;
}

// Interface for QR scan tracking (to prevent duplicate scans)
interface IQRScan extends Document {
    customerId: mongoose.Types.ObjectId;
    qrId: string;
    scannedAt: Date;
}

const QRScanSchema = new mongoose.Schema({
    customerId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Customer',
        required: true
    },
    qrId: {
        type: String,
        required: true
    },
    scannedAt: {
        type: Date,
        default: Date.now
    }
});

// Compound index to prevent duplicate scans
QRScanSchema.index({ customerId: 1, qrId: 1 }, { unique: true });

const QRScan = mongoose.model<IQRScan>('QRScan', QRScanSchema);

// Function to scan QR code using goqr API
async function scanQRCodeFromImage(imageBuffer: Buffer, filename: string): Promise<string> {
    try {
        const formData = new FormData();
        formData.append('file', imageBuffer, {
            filename: filename,
            contentType: getContentType(filename)
        });
        formData.append('outputformat', 'json');

        const response = await axios.post(
            'https://api.qrserver.com/v1/read-qr-code/',
            formData,
            {
                headers: {
                    ...formData.getHeaders(),
                },
                timeout: 15000 // 15 second timeout
            }
        );

        const qrData: GoQRAPIResponse[] = response.data;
        
        if (!qrData || qrData.length === 0) {
            throw new Error('No QR code found in image');
        }

        const firstQR = qrData[0];
        if (!firstQR.symbol || firstQR.symbol.length === 0) {
            throw new Error('No QR code symbols found in image');
        }

        const symbol = firstQR.symbol[0];
        if (symbol.error) {
            throw new Error(`QR code reading failed: ${symbol.error}`);
        }

        if (!symbol.data) {
            throw new Error('QR code contains no readable data');
        }

        return symbol.data;
    } catch (error: any) {
        if (error.response) {
            throw new Error(`QR scanning service error: ${error.response.status} - ${error.response.statusText}`);
        }
        throw new Error(`Failed to scan QR code: ${error.message}`);
    }
}

// Helper function to get content type from filename
function getContentType(filename: string): string {
    const extension = filename.toLowerCase().split('.').pop();
    switch (extension) {
        case 'png': return 'image/png';
        case 'jpg':
        case 'jpeg': return 'image/jpeg';
        case 'gif': return 'image/gif';
        default: return 'image/jpeg';
    }
}

// Middleware to validate customer
async function validateCustomer(customerId: string): Promise<ICustomer> {
    if (!mongoose.Types.ObjectId.isValid(customerId)) {
        throw new Error('Invalid customer ID format');
    }

    const customer = await Customer.findById(customerId);
    if (!customer) {
        throw new Error('Customer not found');
    }

    return customer;
}

// Main QR scanning endpoint
router.post('/scan-qr', upload.single('qrImage'), async (req: Request, res: Response) => {
    try {
        // Validate request inputs
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'QR code image is required',
                error: 'MISSING_QR_IMAGE'
            } as QRScanResponse);
        }

        const customerId = req.body.customerId;
        if (!customerId) {
            return res.status(400).json({
                success: false,
                message: 'Customer ID is required',
                error: 'MISSING_CUSTOMER_ID'
            } as QRScanResponse);
        }

        // Validate customer exists
        let customer: ICustomer;
        try {
            customer = await validateCustomer(customerId);
        } catch (error: any) {
            return res.status(400).json({
                success: false,
                message: error.message,
                error: 'INVALID_CUSTOMER'
            } as QRScanResponse);
        }

        // Scan QR code from uploaded image
        let qrContent: string;
        try {
            qrContent = await scanQRCodeFromImage(req.file.buffer, req.file.originalname);
        } catch (error: any) {
            return res.status(400).json({
                success: false,
                message: `QR code scanning failed: ${error.message}`,
                error: 'QR_SCAN_FAILED'
            } as QRScanResponse);
        }

        // Check if QR code exists in database
        const qrRecord = await QR.findOne({ 
            qrId: qrContent, 
            isActive: true 
        });

        if (!qrRecord) {
            return res.status(404).json({
                success: false,
                message: 'QR code not found or inactive',
                error: 'QR_NOT_FOUND'
            } as QRScanResponse);
        }

        // Check if customer has already scanned this QR code
        const existingScan = await QRScan.findOne({
            customerId: customer._id,
            qrId: qrContent
        });

        if (existingScan) {
            return res.status(409).json({
                success: false,
                message: 'QR code already scanned by this customer',
                error: 'DUPLICATE_SCAN',
                data: {
                    qrId: qrContent,
                    pointsEarned: 0,
                    customerTotalPoints: customer.points,
                    customerName: customer.name
                }
            } as QRScanResponse);
        }

        // Start transaction to ensure data consistency
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            // Record the scan
            const newScan = new QRScan({
                customerId: customer._id,
                qrId: qrContent,
                scannedAt: new Date()
            });
            await newScan.save({ session });

            // Update customer points
            const updatedCustomer = await Customer.findByIdAndUpdate(
                customer._id,
                { $inc: { points: qrRecord.points } },
                { new: true, session }
            );

            if (!updatedCustomer) {
                throw new Error('Failed to update customer points');
            }

            // Commit transaction
            await session.commitTransaction();

            // Return success response
            return res.status(200).json({
                success: true,
                message: 'QR code scanned successfully and points awarded',
                data: {
                    qrId: qrContent,
                    pointsEarned: qrRecord.points,
                    customerTotalPoints: updatedCustomer.points,
                    customerName: updatedCustomer.name
                }
            } as QRScanResponse);

        } catch (error: any) {
            // Rollback transaction on error
            await session.abortTransaction();
            throw error;
        } finally {
            session.endSession();
        }

    } catch (error: any) {
        console.error('QR scan error:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error occurred while processing QR scan',
            error: 'INTERNAL_ERROR'
        } as QRScanResponse);
    }
});

// Endpoint to get customer's scan history
router.get('/scan-history/:customerId', async (req: Request, res: Response) => {
    try {
        const customerId = req.params.customerId;

        // Validate customer
        let customer: ICustomer;
        try {
            customer = await validateCustomer(customerId);
        } catch (error: any) {
            return res.status(400).json({
                success: false,
                message: error.message,
                error: 'INVALID_CUSTOMER'
            });
        }

        // Get scan history with QR details
        const scanHistory = await QRScan.find({ customerId: customer._id })
            .sort({ scannedAt: -1 })
            .limit(50); // Limit to last 50 scans

        const scanHistoryWithDetails = await Promise.all(
            scanHistory.map(async (scan) => {
                const qrRecord = await QR.findOne({ qrId: scan.qrId });
                return {
                    qrId: scan.qrId,
                    scannedAt: scan.scannedAt,
                    pointsEarned: qrRecord ? qrRecord.points : 0,
                    qrActive: qrRecord ? qrRecord.isActive : false
                };
            })
        );

        return res.status(200).json({
            success: true,
            message: 'Scan history retrieved successfully',
            data: {
                customerName: customer.name,
                totalPoints: customer.points,
                totalScans: scanHistory.length,
                scanHistory: scanHistoryWithDetails
            }
        });

    } catch (error: any) {
        console.error('Scan history error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to retrieve scan history',
            error: 'INTERNAL_ERROR'
        });
    }
});

// Endpoint to check QR code status without scanning
router.post('/check-qr', async (req: Request, res: Response) => {
    try {
        const { qrId, customerId } = req.body;

        if (!qrId) {
            return res.status(400).json({
                success: false,
                message: 'QR ID is required',
                error: 'MISSING_QR_ID'
            });
        }

        // Check if QR exists and is active
        const qrRecord = await QR.findOne({ qrId, isActive: true });
        if (!qrRecord) {
            return res.status(404).json({
                success: false,
                message: 'QR code not found or inactive',
                error: 'QR_NOT_FOUND'
            });
        }

        let alreadyScanned = false;
        if (customerId) {
            const existingScan = await QRScan.findOne({ customerId, qrId });
            alreadyScanned = !!existingScan;
        }

        return res.status(200).json({
            success: true,
            message: 'QR code is valid',
            data: {
                qrId,
                points: qrRecord.points,
                isActive: qrRecord.isActive,
                alreadyScanned,
                url: qrRecord.url
            }
        });

    } catch (error: any) {
        console.error('QR check error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to check QR code status',
            error: 'INTERNAL_ERROR'
        });
    }
});

// Export the router and QRScan model for use in other parts of the application
export { router as qrScannerRouter, QRScan };
export default router;