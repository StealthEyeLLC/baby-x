import { request } from 'node:http';
import { MicrovmError } from './errors.ts';
import { canonicalize, sha256, type JsonObject } from '../../core.ts';

export interface FirecrackerApiResponse { statusCode: number; body: JsonObject | null }

export function firecrackerApi(socketPath: string, method: 'PATCH' | 'PUT', path: string, body: JsonObject, timeoutMs = 10_000): Promise<FirecrackerApiResponse> {
  const encoded = Buffer.from(JSON.stringify(body), 'utf8');
  if (encoded.length > 65_536) return Promise.reject(new MicrovmError('microvm_invalid_request', 'Firecracker API request exceeds the configured bound'));
  return new Promise((resolve, reject) => {
    let complete = false;
    const finish = (error?: Error, result?: FirecrackerApiResponse) => {
      if (complete) return;
      complete = true;
      if (error !== undefined) reject(error); else resolve(result as FirecrackerApiResponse);
    };
    const client = request({ socketPath, method, path, headers: { 'Content-Type': 'application/json', 'Content-Length': encoded.length } }, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 65_536) { client.destroy(); finish(new MicrovmError('microvm_provider_unavailable', 'Firecracker API response exceeds the configured bound')); return; }
        chunks.push(chunk);
      });
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed: JsonObject | null = null;
        if (text.length > 0) {
          try { parsed = JSON.parse(text) as JsonObject; }
          catch { finish(new MicrovmError('microvm_provider_unavailable', 'Firecracker API returned invalid JSON')); return; }
        }
        const statusCode = response.statusCode ?? 0;
        if (statusCode < 200 || statusCode >= 300) {
          finish(new MicrovmError('microvm_provider_unavailable', 'Firecracker API request failed', { statusCode, faultDigest: parsed === null ? null : sha256(canonicalize(parsed)) }));
          return;
        }
        finish(undefined, { statusCode, body: parsed });
      });
    });
    client.setTimeout(timeoutMs, () => client.destroy(new Error('deadline exceeded')));
    client.on('error', (error) => finish(new MicrovmError('microvm_provider_unavailable', 'Firecracker API transport failed', { cause: error.message })));
    client.end(encoded);
  });
}
