import { createHmac } from "node:crypto";

import type { FastifyBaseLogger } from "fastify";
import type { AppConfig } from "../config.js";
import { withTransaction, type Database } from "../db/pool.js";

type OutboxEvent = {
  attempts: number;
  id: string;
  payload: Record<string, unknown>;
  topic: string;
};

export class OutboxWorker {
  private stopped = false;
  private running: Promise<void> | undefined;

  public constructor(
    private readonly database: Database,
    private readonly config: AppConfig,
    private readonly log: FastifyBaseLogger,
  ) {}

  public start(): void {
    if (this.running) return;
    this.running = this.loop();
  }

  public async stop(): Promise<void> {
    this.stopped = true;
    await this.running;
  }

  private async loop(): Promise<void> {
    while (!this.stopped) {
      try {
        const events = await this.claim(20);
        if (events.length === 0) {
          await delay(1_000);
          continue;
        }
        for (const event of events) {
          await this.deliver(event);
        }
      } catch (error) {
        this.log.error({ error: safeError(error) }, "outbox worker iteration failed");
        await delay(2_000);
      }
    }
  }

  private async claim(limit: number): Promise<OutboxEvent[]> {
    return withTransaction(this.database, async (client) => {
      const result = await client.query<{
        attempts: number;
        id: string;
        payload: Record<string, unknown>;
        topic: string;
      }>(
        `WITH candidates AS (
           SELECT id FROM outbox_events
            WHERE processed_at IS NULL AND available_at <= now()
              AND attempts < 10
              AND (locked_at IS NULL OR locked_at < now() - interval '5 minutes')
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT $1
         )
         UPDATE outbox_events e
            SET locked_at = now(), attempts = attempts + 1
           FROM candidates c
          WHERE e.id = c.id
         RETURNING e.id, e.topic, e.payload, e.attempts`,
        [limit],
      );
      return result.rows;
    });
  }

  private async deliver(event: OutboxEvent): Promise<void> {
    if (!this.config.outboxWebhookUrl) {
      this.log.warn({ eventId: event.id, topic: event.topic }, "outbox webhook is not configured");
      await this.markFailed(event, "outbox webhook is not configured");
      return;
    }

    const timestamp = Math.floor(Date.now() / 1_000).toString();
    const body = JSON.stringify({ data: event.payload, id: event.id, topic: event.topic });
    const signature = createHmac("sha256", this.config.outboxWebhookSecret)
      .update(`${timestamp}.${body}`)
      .digest("hex");
    try {
      const response = await fetch(this.config.outboxWebhookUrl, {
        body,
        headers: {
          "content-type": "application/json",
          "user-agent": "saas-auth-rbac-backend/0.1",
          "x-auth-event-id": event.id,
          "x-auth-signature": `sha256=${signature}`,
          "x-auth-timestamp": timestamp,
        },
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(5_000),
      });
      if (!response.ok) throw new Error(`Webhook returned HTTP ${response.status}`);
      await this.database.query(
        `UPDATE outbox_events
            SET processed_at = now(), locked_at = NULL, last_error = NULL,
                payload = jsonb_build_object('delivered', true)
          WHERE id = $1`,
        [event.id],
      );
    } catch (error) {
      await this.markFailed(event, safeError(error));
    }
  }

  private async markFailed(event: OutboxEvent, error: string): Promise<void> {
    await this.database.query(
      `UPDATE outbox_events
          SET locked_at = NULL,
              available_at = now() + make_interval(secs => LEAST(3600, power(2, attempts)::integer)),
              last_error = left($2, 1000)
        WHERE id = $1`,
      [event.id, error],
    );
    this.log.warn({ attempts: event.attempts, eventId: event.id, topic: event.topic }, "outbox delivery failed");
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeError(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : "Unknown error";
}
