import mongoose, { Document, Schema } from 'mongoose';

export interface IQR extends Document {
    qrId: string;
    points: number;
    url: string;
    format: string;
    size: string;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
}

const QRSchema: Schema<IQR> = new Schema(
    {
        qrId: {
            type: String,
            required: true,
            unique: true, // ensures no duplicates
            trim: true
        },
        points: {
            type: Number,
            required: true,
            min: 1,
            validate: {
                validator: Number.isInteger,
                message: 'Points must be a whole number'
            }
        },
        url: {
            type: String,
            required: true,
            trim: true,
            validate: {
                validator: function (v: string) {
                    try {
                        new URL(v);
                        return true;
                    } catch (error) {
                        return false;
                    }
                },
                message: 'Invalid URL format'
            }
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
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);


export const QR = mongoose.model<IQR>('QR', QRSchema);