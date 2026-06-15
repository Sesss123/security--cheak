import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import * as nodemailer from 'nodemailer';

@Injectable()
export class AlertService {
  private readonly logger = new Logger(AlertService.name);
  private transporter: nodemailer.Transporter | null = null;

  constructor() {
    this.initTransporter();
  }

  private initTransporter() {
    if (process.env.SMTP_HOST && process.env.SMTP_USER) {
      this.transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      });
      this.logger.log('SMTP Email Transporter initialized.');
    }
  }

  async sendAlert(subject: string, message: string, severity: string): Promise<void> {
    this.logger.log(`[ALERT DISPATCHED] ${severity} - ${subject}`);

    await Promise.allSettled([
      this.sendTelegramAlert(`🚨 *${severity} ALERT* 🚨\n${subject}\n\n${message}`),
      this.sendWebhookAlert({ subject, message, severity }),
      this.sendEmailAlert(subject, message),
    ]);
  }

  private async sendTelegramAlert(text: string): Promise<void> {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    
    if (!botToken || !chatId) {
      this.logger.debug('Telegram alert skipped (No credentials)');
      return;
    }

    try {
      await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        chat_id: chatId,
        text,
        parse_mode: 'Markdown',
      });
    } catch (e: any) {
      this.logger.error(`Telegram alert failed: ${e.message}`);
    }
  }

  private async sendWebhookAlert(payload: any): Promise<void> {
    const webhookUrl = process.env.WEBHOOK_URL;
    if (!webhookUrl) return;

    try {
      await axios.post(webhookUrl, payload);
    } catch (e: any) {
      this.logger.error(`Webhook alert failed: ${e.message}`);
    }
  }

  private async sendEmailAlert(subject: string, text: string): Promise<void> {
    if (!this.transporter || !process.env.ALERT_EMAIL_TO) {
       this.logger.debug('Email alert skipped (No credentials/recipient)');
       return;
    }

    try {
      await this.transporter.sendMail({
        from: process.env.SMTP_FROM || 'alerts@securityplatform.local',
        to: process.env.ALERT_EMAIL_TO,
        subject: `[SECURITY ALERT] ${subject}`,
        text,
      });
    } catch (e: any) {
      this.logger.error(`Email alert failed: ${e.message}`);
    }
  }
}
