import mongoose, { Document, Schema } from 'mongoose';

// Interface for Customer document
export interface ICustomer extends Document {
    name: string;
    city: string;
    username: string;
    phone: string;
    email?: string;  // optional
    password: string;
    points: number;
    resetPasswordToken?: string;
    resetPasswordExpires?: Date;
    createdAt: Date;
    updatedAt: Date;
}

// Customer Schema
const CustomerSchema: Schema<ICustomer> = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    city: {
        type: String,
        required: true,
        trim: true
    },
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    phone: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        match: [
            /^[0-9]{10}$/, // simple regex for 10-digit numbers, tweak if needed
            'Please enter a valid phone number'
        ]
    },
    email: {
        type: String,
        required: false,   // ✅ email now optional
        unique: true,
        sparse: true,      // ✅ avoids index conflict when many docs have no email
        trim: true,
        lowercase: true,
        match: [
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
            'Please enter a valid email address'
        ]
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    points: {
        type: Number,
        default: 0,
        min: 0
    },
    resetPasswordToken: {
        type: String,
        default: undefined
    },
    resetPasswordExpires: {
        type: Date,
        default: undefined
    }
}, {
    timestamps: true
});

// Create and export the model
const Customer = mongoose.model<ICustomer>('Customer', CustomerSchema);

export default Customer;
