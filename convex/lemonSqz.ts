'use node';

import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import { createHmac } from 'crypto';

const webhook = process.env.LEMON_SQUEEZY_WEBHOOK_SECRET || 'lemon-sqz';
function verifySignature(payload: string, signature: string) {
  const hmac = createHmac('sha256', webhook);
  const computedSignature = hmac.update(payload).digest('hex');
  return signature === computedSignature;
}

export const verifyWebhook = internalAction({
  args: {
    payload: v.string(),
    signature: v.string(),
  },
  handler: async (ctx, args) => {
    const isValid = verifySignature(args.payload, args.signature);
    if (!isValid) {
      throw new Error('Invalid signature');
    }
    const payload = JSON.parse(args.payload);
    return payload;
  },
});
