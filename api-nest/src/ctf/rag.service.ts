import { Injectable } from '@nestjs/common';
import { GoogleGenerativeAI } from '@google/generative-ai';

@Injectable()
export class RagService {
  private genAI: GoogleGenerativeAI;

  constructor() {
    // Initialize with standard process.env if available, fallback for safety
    this.genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || 'dummy_key');
  }

  async query(userQuery: string) {
    try {
        // In a real RAG setup, you would query Qdrant here to get context.
        // For now, we simulate this.
        const simulatedContext = "CTF challenges often use base64 encoding for hidden cookies. To solve this, decode the cookie, change admin=false to admin=true, and re-encode.";

        const model = this.genAI.getGenerativeModel({ model: "gemini-1.5-pro" });
        const prompt = `You are an expert CTF assistant. Use the provided context to answer the user's query. If the context doesn't have the answer, use your general knowledge but mention that it's not from the specific CTF writeups database.
        
        Context: ${simulatedContext}
        
        User Query: ${userQuery}`;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();

        return {
            query: userQuery,
            answer: text,
            sources: ['Simulated CTF Writeup Database (Qdrant)']
        };
    } catch (error) {
        console.error("RAG Query Error:", error);
        return {
             query: userQuery,
             answer: "I couldn't process the query. Please ensure your AI API keys are configured correctly.",
             sources: []
        }
    }
  }
}
