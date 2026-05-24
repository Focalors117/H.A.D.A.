import { Schema, model, type InferSchemaType } from 'mongoose';

const ScanSchema = new Schema(
  {
    assetId: {
      type: Schema.Types.ObjectId,
      ref: 'Asset',
      required: true,
      index: true,
    },
    ip: { type: String, required: true },
    detectionSource: {
      type: String,
      enum: ['ARP', 'TTL', 'MANUAL'],
      default: 'MANUAL',
    },
    status: {
      type: String,
      enum: ['Active', 'Down', 'Compromised'],
      default: 'Active',
    },
    lastScanAt: { type: Date, required: true, default: Date.now },
    lastScanMode: {
      type: String,
      enum: ['normal', 'stealth'],
      required: false,
    },
    networkId: {
      type: String,
      required: true,
      default: 'default',
      index: true,
    },
  },
  { timestamps: true }
);

ScanSchema.index({ assetId: 1, lastScanAt: -1 });
ScanSchema.index({ ip: 1, networkId: 1, lastScanAt: -1 });

export type ScanDocument = InferSchemaType<typeof ScanSchema>;
export const Scan = model('Scan', ScanSchema);
