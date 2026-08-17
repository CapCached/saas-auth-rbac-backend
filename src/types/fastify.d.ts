import "fastify";

import type { Principal } from "../store/types.js";

declare module "fastify" {
  interface FastifyRequest {
    organizationId?: string;
    principal?: Principal;
  }
}
