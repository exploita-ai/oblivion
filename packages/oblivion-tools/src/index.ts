import { StdioServerTransport } from "@modelcontextprotocol/server/stdio"
import { createServer } from "./server"
import { discoverSafeTools } from "./safe-tools"

// stdout belongs exclusively to MCP. No request, credential or HTTP error is
// logged. The enclosing agent service owns this process and its descendants.
const server = createServer(await discoverSafeTools())
const transport = new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 64 * 1024 })
transport.onerror = () => {}
server.server.onerror = () => {}
await server.connect(transport)
