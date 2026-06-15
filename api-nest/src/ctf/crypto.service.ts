import { Injectable } from '@nestjs/common';

@Injectable()
export class CryptoService {
  analyze(input: string) {
    const results: { type: string; confidence: string; decoded: string; hint: string }[] = [];

    // 1. Check Base64
    if (this.isBase64(input)) {
      try {
        const decoded = Buffer.from(input, 'base64').toString('utf-8');
        results.push({
          type: 'Base64',
          confidence: 'High',
          decoded,
          hint: this.generateHint(decoded),
        });
      } catch (e) {
        // Not base64
      }
    }

    // 2. Check Hex
    if (this.isHex(input)) {
      try {
        const decoded = Buffer.from(input, 'hex').toString('utf-8');
        results.push({
          type: 'Hexadecimal',
          confidence: 'High',
          decoded,
          hint: this.generateHint(decoded),
        });
      } catch (e) {
        // Not hex
      }
    }

    // 3. ROT13
    const rot13 = input.replace(/[a-zA-Z]/g, (c) => {
      const charCode = c.charCodeAt(0);
      const isUpperCase = c <= 'Z';
      const maxCode = isUpperCase ? 90 : 122;
      const newCode = charCode + 13;
      return String.fromCharCode(maxCode >= newCode ? newCode : newCode - 26);
    });
    if (rot13 !== input) {
       results.push({
          type: 'ROT13',
          confidence: 'Medium',
          decoded: rot13,
          hint: this.generateHint(rot13),
        });
    }

    return {
      original: input,
      analysis: results,
      aiSummary: results.length > 0 
        ? `Found ${results.length} possible encodings. Try checking the decoded outputs for flags.`
        : 'Could not identify the encoding. It might be a complex cipher or hash.',
    };
  }

  private isBase64(str: string): boolean {
    if (str === '' || str.trim() === '') return false;
    try {
      return btoa(atob(str)) === str;
    } catch (err) {
      return false;
    }
  }

  private isHex(str: string): boolean {
    return /^[0-9A-Fa-f]+$/.test(str) && str.length % 2 === 0;
  }

  private generateHint(decoded: string): string {
      if (decoded.includes('flag{') || decoded.includes('CTF{') || decoded.includes('}')) {
          return "This looks like a flag!";
      }
      if (decoded.includes('http')) {
          return "This looks like a URL. Try visiting it.";
      }
      return "Review this decoded output.";
  }
}
