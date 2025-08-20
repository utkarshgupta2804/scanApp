import mongoose, { Document, Schema } from 'mongoose';

export interface IScheme extends Document {
  title: string;
  description: string;
  images: string[];
  pointsRequired: number;
  createdAt: Date;
  updatedAt: Date;
}
const SchemeSchema: Schema<IScheme> = new Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200
    },
    description: {
      type: String,
      required: true,
      trim: true,
      maxlength: 1000
    },
    images: [{
      type: String,
      required: true,
      validate: {
        validator: function(v: string) {
          // Basic URL validation or file path validation
          return /^(https?:\/\/|\/|\.\/|\.\.\/).*\.(jpg|jpeg|png|gif|webp)$/i.test(v);
        },
        message: 'Invalid image URL or path format'
      }
    }],
    pointsRequired: {
      type: Number,
      required: true,
      min: 0,
      validate: {
        validator: Number.isInteger,
        message: 'Points required must be a whole number'
      }
    },
  },
  {
    timestamps: true,
    versionKey: false
  }
);

export const Scheme = mongoose.model<IScheme>('Scheme', SchemeSchema);