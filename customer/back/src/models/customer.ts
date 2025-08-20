import mongoose, { Document, Schema } from 'mongoose';

// Interface for Customer document
export interface ICustomer extends Document {
    name: string;
    city: string;
    username: string;
    password: string;
    points: number;
    createdAt: Date;
    updatedAt: Date;
}

// Customer Schema
const CustomerSchema: Schema<ICustomer> = new Schema({
    name: {
        type: String,
        required: true
    },
    city: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    points: {
        type: Number,
        default: 0,
        min: 0
    }
}, {
    timestamps: true
});

// Create and export the model
const Customer = mongoose.model<ICustomer>('Customer', CustomerSchema);

export default Customer;