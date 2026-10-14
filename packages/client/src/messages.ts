// Formato do conteúdo das mensagens. Este JSON é preenchido (padding) e
// cifrado de ponta a ponta; o servidor nunca o vê.

export type MessageKind = 'text' | 'image' | 'voice';

export interface AttachmentPointer {
  /** ID do arquivo cifrado no servidor. */
  id: string;
  /** Chave AES-256 (base64). */
  key: string;
  /** SHA-256 do arquivo cifrado (base64). */
  digest: string;
  mime: string;
  size: number;
  width?: number;
  height?: number;
  durationMs?: number;
}

export interface Payload {
  v: 1;
  /** ID gerado pelo remetente; o mesmo para todos os destinatários. */
  id: string;
  kind: MessageKind;
  text?: string;
  attachment?: AttachmentPointer;
  groupId?: string;
  /** registration_id da instalação do remetente (autenticado pela cifra). */
  senderRegistrationId: number;
  /** Horário de envio no aparelho do remetente (ms desde a época). */
  sentAt: number;
}

export interface ReceivedMessage extends Payload {
  from: string;
  envelopeId: string;
  serverTimestamp: string;
}

export function validatePayload(p: unknown): Payload {
  const o = p as Payload;
  if (
    !o ||
    o.v !== 1 ||
    typeof o.id !== 'string' ||
    typeof o.sentAt !== 'number' ||
    !Number.isInteger(o.senderRegistrationId)
  ) {
    throw new Error('conteúdo de mensagem inválido');
  }
  switch (o.kind) {
    case 'text':
      if (typeof o.text !== 'string') throw new Error('mensagem de texto sem texto');
      break;
    case 'image':
    case 'voice': {
      const a = o.attachment;
      if (!a || typeof a.id !== 'string' || typeof a.key !== 'string' || typeof a.digest !== 'string') {
        throw new Error('anexo inválido');
      }
      break;
    }
    default:
      throw new Error('tipo de mensagem desconhecido');
  }
  return o;
}
