import { Controller, Post, Body, Headers, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

@Controller('webhook')
export class WebhookController {
  private readonly logger = new Logger(WebhookController.name);

  private readonly webhookSecret =
    process.env.GITHUB_WEBHOOK_SECRET || 'your-secret-key';

  @Post()
  handleWebhook(
    @Body() payload: any,
    @Headers('x-hub-signature-256') signature: string,
  ): string {
    if (!this.isValidSignature(payload, signature)) {
      this.logger.warn('Assinatura inválida! Possível tentativa de ataque.');
      return 'Invalid signature';
    }

    this.logger.log(`Evento recebido: ${payload.action}`);
    this.processEvent(payload);

    return 'Webhook recebido com sucesso!';
  }

  private isValidSignature(payload: any, signature: string): boolean {
    const computedSignature = `sha256=${crypto
      .createHmac('sha256', this.webhookSecret)
      .update(JSON.stringify(payload))
      .digest('hex')}`;

    return crypto.timingSafeEqual(
      Buffer.from(signature || ''),
      Buffer.from(computedSignature),
    );
  }

  private processEvent(payload: any) {
    switch (payload.action) {
      case 'opened':
        this.logger.log(`Issue aberta: ${payload.issue.title}`);
        break;
      case 'closed':
        this.logger.log(`Issue fechada: ${payload.issue.title}`);
        break;
      default:
        this.logger.log(`Evento desconhecido: ${payload.action}`);
    }
  }
}
