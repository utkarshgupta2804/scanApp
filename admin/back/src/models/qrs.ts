import mongoose, { Document, Schema } from 'mongoose';

// Individual QR code interface within a batch
export interface IQRItem {
    qrId: string;
    qrCodeUrl: string;
    isScanned: boolean;  // New attribute to track if QR is scanned
}

// Main QR Batch interface
export interface IQRBatch extends Document {
    batchId: string;
    qrData: string;  // Common data for all QRs in batch (Points: X\nURL: Y)
    format: string;
    size: string;
    qrCodes: IQRItem[];  // Array of individual QR codes
    totalCount: number;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
}

const QRItemSchema = new Schema<IQRItem>({
    qrId: {
        type: String,
        required: true,
        trim: true
    },
    qrCodeUrl: {
        type: String,
        required: true
    },
    isScanned: {
        type: Boolean,
        default: false,  // Default to false when QR is created
        required: true
    }
}, { _id: false }); // Don't create separate _id for array items

const QRBatchSchema: Schema<IQRBatch> = new Schema(
    {
        batchId: {
            type: String,
            required: true,
            unique: true,
            trim: true
        },
        qrData: {
            type: String,
            required: true
        },
        format: {
            type: String,
            required: true,
            lowercase: true,
            enum: ['png', 'jpg', 'jpeg', 'svg'],
            default: 'png'
        },
        size: {
            type: String,
            required: true,
            validate: {
                validator: function (v: string) {
                    const sizePattern = /^\d+x\d+$/;
                    if (!sizePattern.test(v)) return false;
                    const [width, height] = v.split('x').map(Number);
                    return width === height && width >= 10 && width <= 1000000;
                },
                message: 'Size must be in format WIDTHxHEIGHT and be square'
            },
            default: '200x200'
        },
        qrCodes: [QRItemSchema],
        totalCount: {
            type: Number,
            required: true,
            min: 1
        },
        isActive: {
            type: Boolean,
            default: true
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

export const QRBatch = mongoose.model<IQRBatch>('QRBatch', QRBatchSchema);