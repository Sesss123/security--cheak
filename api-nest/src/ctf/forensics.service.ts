import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

@Injectable()
export class ForensicsService {
  private readonly uploadPath = path.join(process.cwd(), 'uploads', 'forensics');

  constructor() {
    // Ensure upload directory exists
    if (!fs.existsSync(this.uploadPath)) {
      fs.mkdirSync(this.uploadPath, { recursive: true });
    }
  }

  async analyzeFile(file: Express.Multer.File) {
    if (!file) {
      throw new Error('No file provided');
    }

    const fileHash = crypto.createHash('md5').update(file.buffer).digest('hex');
    const fileName = `${fileHash}_${file.originalname}`;
    const filePath = path.join(this.uploadPath, fileName);

    // Save the file
    fs.writeFileSync(filePath, file.buffer);

    // Perform basic static analysis
    const analysis = {
      filename: file.originalname,
      size: file.size,
      mimetype: file.mimetype,
      md5: fileHash,
      sha256: crypto.createHash('sha256').update(file.buffer).digest('hex'),
      magicBytes: file.buffer.toString('hex', 0, 4),
      entropy: this.calculateEntropy(file.buffer),
      strings: this.extractStrings(file.buffer),
    };

    return analysis;
  }

  private calculateEntropy(buffer: Buffer): number {
    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) {
      frequencies[buffer[i]]++;
    }

    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / buffer.length;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }

  private extractStrings(buffer: Buffer, minLength: number = 5): string[] {
    const text = buffer.toString('ascii');
    // Basic regex to find printable ASCII strings
    const regex = new RegExp(`[\\x20-\\x7E]{${minLength},}`, 'g');
    const matches = text.match(regex);
    
    if (!matches) return [];

    // Filter out obvious noise and limit to 50 interesting strings
    return matches
        .filter(s => s.trim().length >= minLength)
        .slice(0, 50);
  }
}
