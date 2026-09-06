// Servidor MCP mínimo para los tests de toolgate.
// Habla JSON-RPC 2.0 por stdio, delimitado por saltos de línea: responde
// `initialize` y `tools/list`, y nada más.
//
// El salto de línea se construye con fromCharCode para que el fichero no
// dependa de secuencias de escape al generarse.
const NL = String.fromCharCode(10);

function send(message) {
  process.stdout.write(JSON.stringify(message) + NL);
}

let buffer = '';
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf(NL)) >= 0) {
    const line = buffer.slice(0, index);
    buffer = buffer.slice(index + 1);
    if (!line.trim()) continue;

    let message;
    try {
      message = JSON.parse(line);
    } catch (e) {
      continue;
    }

    if (message.method === 'initialize') {
      send({
        jsonrpc: '2.0',
        id: message.id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          serverInfo: { name: 'fake', version: '1.0.0' },
        },
      });
    }

    if (message.method === 'tools/list') {
      send({
        jsonrpc: '2.0',
        id: message.id,
        result: {
          tools: [
            {
              name: 'ping',
              description: 'Responde pong.',
              inputSchema: { type: 'object' },
            },
          ],
        },
      });
    }
  }
});
