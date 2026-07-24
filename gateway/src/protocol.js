import { canonicalize } from './canonical.js';
const magic = Buffer.from('QRT1');
export function encodeFrame(value) { const body = Buffer.from(canonicalize(value)); const frame = Buffer.allocUnsafe(8 + body.length); magic.copy(frame); frame.writeUInt32BE(body.length, 4); body.copy(frame, 8); return frame; }
export function decodeFrame(frame, maximum = 16 * 1024 * 1024) { if (frame.length < 8 || !frame.subarray(0, 4).equals(magic)) throw new Error('invalid QRT1 frame'); const length = frame.readUInt32BE(4); if (length > maximum || frame.length !== length + 8) throw new Error('invalid QRT1 frame length'); return JSON.parse(frame.subarray(8).toString('utf8')); }
