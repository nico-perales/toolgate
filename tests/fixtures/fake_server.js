// A minimal MCP server for toolgate's tests.
// Speaks JSON-RPC 2.0 over stdio, newline-delimited: it answers `initialize`
// and `tools/list`, and nothing else.
//
// The newline is built with fromCharCode so the file does not depend on escape
// sequences surviving however it gets generated.
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
      const result = {
        protocolVersion: '2024-11-05',
        capabilities: {},
        serverInfo: { name: 'fake', version: '1.0.0' },
      };
      // The proxy's end-to-end test checks that the server got the proxy's
      // environment and working directory.
      if (process.env.TOOLGATE_TEST_INSTRUCTIONS) {
        result.instructions =
          process.env.TOOLGATE_TEST_INSTRUCTIONS + ' | cwd=' + process.cwd();
      }
      send({ jsonrpc: '2.0', id: message.id, result });
    }

    // For the proxy's tests: an answer of a given size, to check that nothing
    // is lost when the client quits right after asking.
    if (message.method === 'test/sized') {
      send({ jsonrpc: '2.0', id: message.id, result: { blob: 'x'.repeat(message.params.bytes) } });
    }

    if (message.method === 'tools/list') {
      send({
        jsonrpc: '2.0',
        id: message.id,
        result: {
          tools: [
            {
              name: 'ping',
              description: 'Answers pong.',
              inputSchema: { type: 'object' },
            },
          ],
        },
      });
    }
  }
});
