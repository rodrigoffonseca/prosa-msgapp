// Preenchimento (padding) do texto antes de cifrar, para que o tamanho da
// mensagem cifrada não revele o tamanho exato do conteúdo.

const BLOCK = 160;

export function pad(data: Uint8Array): Uint8Array {
  const len = Math.ceil((data.length + 1) / BLOCK) * BLOCK;
  const out = new Uint8Array(len);
  out.set(data);
  out[data.length] = 0x80;
  return out;
}

export function unpad(data: Uint8Array): Uint8Array {
  for (let i = data.length - 1; i >= 0; i--) {
    if (data[i] === 0x80) return data.slice(0, i);
    if (data[i] !== 0) break;
  }
  throw new Error('preenchimento inválido');
}
