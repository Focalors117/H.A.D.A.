import { Schema, model, type InferSchemaType } from 'mongoose';

const ServiceSchema = new Schema(
  {
    assetId: {
      type: Schema.Types.ObjectId,
      ref: 'Asset',
      required: true,
      index: true,
    },
    port: { type: Number, required: true },
    banner: { type: String, default: '' },
    fingerprint: { type: String, default: '' },
    networkId: {
      type: String,
      required: true,
      default: 'default',
      index: true,
    },
  },
  { timestamps: true }
);

ServiceSchema.index({ assetId: 1, port: 1 }, { unique: true });

export type ServiceDocument = InferSchemaType<typeof ServiceSchema>;
export const Service = model('Service', ServiceSchema);
